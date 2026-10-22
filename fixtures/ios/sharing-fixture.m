#import <UIKit/UIKit.h>
#import <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef FIXTURE_VERSION
#define FIXTURE_VERSION "1"
#endif

// These are deliberately the original developer's literal identifiers. The
// fixture does not read the signer's aliases or substituted Info.plist values.
static NSString *const appGroup = @"group.org.ipaloader.sharingfixture";
static NSString *const keychainGroup = @"OLDTEAM001.org.ipaloader.sharingfixture";

static NSDictionary *sharingCheck(BOOL extension) {
    NSURL *directory = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:appGroup];
    NSUserDefaults *suite = [[NSUserDefaults alloc] initWithSuiteName:appGroup];
    NSURL *file = [directory URLByAppendingPathComponent:@"sharing-state.json"];
    NSData *disk = file ? [NSData dataWithContentsOfURL:file] : nil;
    NSDictionary *state = disk ? [NSJSONSerialization JSONObjectWithData:disk options:0 error:nil] : nil;
    BOOL preserved = state != nil;
    NSDictionary *query = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:@"org.ipaloader.sharingfixture",
        (__bridge id)kSecAttrAccount:@"shared-state", (__bridge id)kSecAttrAccessGroup:keychainGroup};
    NSMutableDictionary *read = query.mutableCopy;
    read[(__bridge id)kSecReturnData] = @YES;
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)read,&result);
    NSData *secret = CFBridgingRelease(result);
    if (!state && !extension && directory && status == errSecItemNotFound) {
        state = @{ @"nonce":NSUUID.UUID.UUIDString, @"counter":@0 };
        NSData *data = [NSJSONSerialization dataWithJSONObject:state options:0 error:nil];
        NSMutableDictionary *add = query.mutableCopy;
        add[(__bridge id)kSecValueData] = data;
        add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
        status = SecItemAdd((__bridge CFDictionaryRef)add,NULL);
        if (status == errSecSuccess) {
            secret = data;
            [data writeToURL:file atomically:YES];
            [suite setInteger:0 forKey:@"fixture.shared-counter"];
            [suite synchronize];
        }
    }
    NSDictionary *keyState = secret ? [NSJSONSerialization JSONObjectWithData:secret options:0 error:nil] : nil;
    NSInteger counter = [state[@"counter"] integerValue];
    BOOL keyOK = status == errSecSuccess && state && [state isEqual:keyState];
    NSNumber *storedCounter = [suite objectForKey:@"fixture.shared-counter"];
    BOOL suiteOK = [storedCounter isKindOfClass:NSNumber.class] && storedCounter.integerValue == counter;
    BOOL groupOK = directory && state;
    BOOL scratchOK = !extension;
    if (extension && groupOK && keyOK && suiteOK) {
        state = @{ @"nonce":state[@"nonce"], @"counter":@(counter+1) };
        NSData *data = [NSJSONSerialization dataWithJSONObject:state options:0 error:nil];
        status = SecItemUpdate((__bridge CFDictionaryRef)query,
            (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});
        keyOK = status == errSecSuccess;
        groupOK = [data writeToURL:file atomically:YES];
        [suite setInteger:counter+1 forKey:@"fixture.shared-counter"];
        // Synchronize's return value is not a persistence assertion. Verify the
        // value here; the host and device acceptance harness independently
        // check the other process and the on-disk suite after completion.
        [suite synchronize];
        storedCounter = [suite objectForKey:@"fixture.shared-counter"];
        suiteOK = [storedCounter isKindOfClass:NSNumber.class] && storedCounter.integerValue == counter+1;
        counter++;
        NSMutableDictionary *scratch = query.mutableCopy;
        scratch[(__bridge id)kSecAttrAccount] = NSUUID.UUID.UUIDString;
        scratch[(__bridge id)kSecValueData] = [@"owned scratch item" dataUsingEncoding:NSUTF8StringEncoding];
        OSStatus added = SecItemAdd((__bridge CFDictionaryRef)scratch,NULL);
        [scratch removeObjectForKey:(__bridge id)kSecValueData];
        scratchOK = added == errSecSuccess && SecItemDelete((__bridge CFDictionaryRef)scratch) == errSecSuccess;
    }
    BOOL allOK = groupOK && keyOK && suiteOK && scratchOK;
    NSDictionary *proof = @{ @"build":@FIXTURE_VERSION, @"extension":@(extension),
        @"all_ok":@(allOK), @"app_group_ok":@(groupOK), @"keychain_ok":@(keyOK),
        @"suite_ok":@(suiteOK), @"counter":@(counter), @"preserved":@(preserved),
        @"keychain_status":@(status), @"scratch_deleted":@(scratchOK) };
    NSURL *documents = [NSFileManager.defaultManager URLForDirectory:NSDocumentDirectory
        inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:nil];
    [[NSJSONSerialization dataWithJSONObject:proof options:0 error:nil]
        writeToURL:[documents URLByAppendingPathComponent:@"sharing-proof.json"] atomically:YES];
    return proof;
}

#ifdef SHARING_EXTENSION
@interface SharingController : UIViewController
@end
@implementation SharingController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    NSDictionary *proof = sharingCheck(YES);
    UILabel *label = [UILabel new];
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.text = [NSString stringWithFormat:@"Sharing %@\nCounter: %@\nKeychain status: %@",
        [proof[@"all_ok"] boolValue] ? @"verified" : @"FAILED",proof[@"counter"],proof[@"keychain_status"]];
    UIButton *done = [UIButton buttonWithType:UIButtonTypeSystem];
    [done setTitle:@"Finish sharing test" forState:UIControlStateNormal];
    [done addTarget:self action:@selector(finish) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[label,done]];
    stack.axis = UILayoutConstraintAxisVertical;stack.spacing = 24;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor]
    ]];
}
- (void)finish { [self.extensionContext completeRequestReturningItems:@[] completionHandler:nil]; }
@end
#else
@interface SharingHost : UIViewController
@property(nonatomic,strong) UILabel *status;
@end
@implementation SharingHost
- (void)viewDidLoad {
    [super viewDidLoad];self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.status = [UILabel new];self.status.numberOfLines = 0;self.status.textAlignment = NSTextAlignmentCenter;
    UIButton *test = [UIButton buttonWithType:UIButtonTypeSystem];
    [test setTitle:@"Run sharing extension" forState:UIControlStateNormal];
    [test addTarget:self action:@selector(test:) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[self.status,test]];
    stack.axis = UILayoutConstraintAxisVertical;stack.spacing = 24;stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor]
    ]];
    [self refresh];
}
- (void)refresh {
    NSDictionary *proof = sharingCheck(NO);
    self.status.text = [NSString stringWithFormat:@"Sharing Test · Build %s\n%@ · Counter: %@",
        FIXTURE_VERSION,[proof[@"all_ok"] boolValue] ? @"Shared storage verified" : @"Shared storage FAILED",proof[@"counter"]];
}
- (void)test:(UIButton *)button {
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:@[@"IPA Loader sharing test"] applicationActivities:nil];
    activity.popoverPresentationController.sourceView = button;
    activity.completionWithItemsHandler = ^(UIActivityType type,BOOL done,NSArray *items,NSError *error){[self refresh];};
    [self presentViewController:activity animated:YES completion:nil];
}
@end
@interface SharingDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic,strong) UIWindow *window;
@end
@implementation SharingDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    NSDictionary *proof = sharingCheck(NO);
    printf("IPA_LOADER_SHARING_HOST build=%s shared=%s\n",FIXTURE_VERSION,[proof[@"all_ok"] boolValue] ? "ok" : "failed");
    fflush(stdout);
    if ([NSProcessInfo.processInfo.arguments containsObject:@"--fixture-check"]) exit([proof[@"all_ok"] boolValue] ? 0 : 1);
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [SharingHost new];[self.window makeKeyAndVisible];return YES;
}
@end
int main(int argc,char **argv) { @autoreleasepool {return UIApplicationMain(argc,argv,nil,NSStringFromClass(SharingDelegate.class));} }
#endif
