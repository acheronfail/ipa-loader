//go:build ios
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#include <stdlib.h>
#include <string.h>

// Keep one observed manager. Re-loading preferences on each status notification
// can itself emit more status notifications and create an update feedback loop.
static NSLock *ipaVPNCacheLock;
static NETunnelProviderManager *ipaVPNCache;
static BOOL ipaVPNCacheLoaded;
static NSLock *ipaVPNLock(void) {
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    ipaVPNCacheLock = [NSLock new];
  });
  return ipaVPNCacheLock;
}
static void ipaVPNRemember(NETunnelProviderManager *manager) {
  NSLock *lock = ipaVPNLock();
  [lock lock];
  ipaVPNCache = manager;
  ipaVPNCacheLoaded = YES;
  [lock unlock];
}
void ipa_ios_vpn_invalidate(void) {
  NSLock *lock = ipaVPNLock();
  [lock lock];
  ipaVPNCacheLoaded = NO;
  [lock unlock];
}
int ipa_ios_has_vpn(void) {
  NSString *path = [NSBundle.mainBundle.builtInPlugInsPath
      stringByAppendingPathComponent:@"IPALoaderTunnel.appex"];
  return path && [NSFileManager.defaultManager fileExistsAtPath:path];
}
// Called on a Go worker, never UIKit's main thread. Callback-owned objects
// remain alive if loading or the system's consent dialog outlives the timeout.
static char *ipa_ios_connect_vpn_unlocked(void) {
  if (NSThread.isMainThread)
    return strdup("Connect the VPN from a background task");
  NSString *provider =
      [NSBundle.mainBundle.bundleIdentifier stringByAppendingString:@".tunnel"];
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  __block NSString *failure = nil;
  __block NETunnelProviderManager *chosen = nil;
  [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(
                               NSArray<NETunnelProviderManager *> *managers,
                               NSError *error) {
    if (error) {
      failure = error.localizedDescription;
      dispatch_semaphore_signal(done);
      return;
    }
    for (NETunnelProviderManager *manager in managers) {
      NETunnelProviderProtocol *protocol =
          (NETunnelProviderProtocol *)manager.protocolConfiguration;
      if ([protocol isKindOfClass:NETunnelProviderProtocol.class] &&
          [protocol.providerBundleIdentifier isEqualToString:provider]) {
        chosen = manager;
        break;
      }
    }
    if (chosen && chosen.enabled) {
      dispatch_semaphore_signal(done);
      return;
    }
    if (!chosen)
      chosen = [NETunnelProviderManager new];
    NETunnelProviderProtocol *protocol = [NETunnelProviderProtocol new];
    protocol.providerBundleIdentifier = provider;
    protocol.serverAddress = @"This iPhone";
    chosen.protocolConfiguration = protocol;
    chosen.localizedDescription = @"IPA Loader";
    chosen.enabled = YES;
    [chosen saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
      if (saveError) {
        failure = saveError.localizedDescription;
        dispatch_semaphore_signal(done);
        return;
      }
      [chosen loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
        failure = loadError.localizedDescription;
        dispatch_semaphore_signal(done);
      }];
    }];
  }];
  if (dispatch_semaphore_wait(
          done, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC)))
    return strdup("VPN setup timed out. Allow IPA Loader's VPN configuration, "
                  "then try again");
  if (failure)
    return strdup(failure.UTF8String);
  if (!chosen)
    return strdup("The IPA Loader VPN configuration is missing");
  ipaVPNRemember(chosen);
  if (chosen.connection.status == NEVPNStatusConnected)
    return NULL;
  NSError *startError = nil;
  if (![chosen.connection startVPNTunnelAndReturnError:&startError])
    return strdup(
        (startError.localizedDescription ?: @"Could not start IPA Loader VPN")
            .UTF8String);
  for (int i = 0; i < 150; i++) {
    NEVPNStatus status = chosen.connection.status;
    if (status == NEVPNStatusConnected)
      return NULL;
    if (status == NEVPNStatusInvalid || status == NEVPNStatusDisconnecting)
      break;
    [NSThread sleepForTimeInterval:0.1];
  }
  return strdup("IPA Loader VPN did not connect. Disconnect LocalDevVPN or "
                "another VPN, then try again");
}

char *ipa_ios_connect_vpn(void) {
  if (NSThread.isMainThread)
    return strdup("Connect the VPN from a background task");
  static NSLock *lock;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    lock = [NSLock new];
  });
  [lock lock];
  @try {
    return ipa_ios_connect_vpn_unlocked();
  } @finally {
    [lock unlock];
  }
}

// Read only: querying status never creates a configuration or starts a tunnel.
static NETunnelProviderManager *ipaVPNManager(void) {
  if (NSThread.isMainThread)
    return nil;
  NSLock *lock = ipaVPNLock();
  [lock lock];
  if (ipaVPNCacheLoaded) {
    NETunnelProviderManager *manager = ipaVPNCache;
    [lock unlock];
    return manager;
  }
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  __block NETunnelProviderManager *chosen = nil;
  NSString *provider =
      [NSBundle.mainBundle.bundleIdentifier stringByAppendingString:@".tunnel"];
  [NETunnelProviderManager
      loadAllFromPreferencesWithCompletionHandler:^(
          NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        if (!error)
          for (NETunnelProviderManager *manager in managers) {
            NETunnelProviderProtocol *protocol =
                (NETunnelProviderProtocol *)manager.protocolConfiguration;
            if ([protocol isKindOfClass:NETunnelProviderProtocol.class] &&
                [protocol.providerBundleIdentifier isEqual:provider]) {
              chosen = manager;
              break;
            }
          }
        dispatch_semaphore_signal(done);
      }];
  if (dispatch_semaphore_wait(
          done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [lock unlock];
    return nil;
  }
  ipaVPNCache = chosen;
  ipaVPNCacheLoaded = YES;
  [lock unlock];
  return chosen;
}
int ipa_ios_vpn_connected(void) {
  return ipaVPNManager().connection.status == NEVPNStatusConnected;
}
int ipa_ios_disconnect_vpn(void) {
  NETunnelProviderManager *manager = ipaVPNManager();
  [manager.connection stopVPNTunnel];
  for (int i = 0; i < 50; i++) {
    NEVPNStatus status = manager.connection.status;
    if (status == NEVPNStatusDisconnected || status == NEVPNStatusInvalid ||
        !manager)
      return 1;
    [NSThread sleepForTimeInterval:0.1];
  }
  return 0;
}
