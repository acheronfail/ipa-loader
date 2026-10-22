//go:build ios
#import "controls_ios.h"
#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <stdlib.h>
#include <string.h>
char *ipa_ios_home(void) {
  @autoreleasepool {
    return strdup(NSHomeDirectory().fileSystemRepresentation);
  }
}
char *ipa_ios_bundle(void) {
  @autoreleasepool {
    return strdup(NSBundle.mainBundle.bundleIdentifier.UTF8String);
  }
}

@interface IPALoaderPicker : NSObject <UIDocumentPickerDelegate>
@property dispatch_semaphore_t done;
@property char *selected;
@property BOOL failed;
@end
@implementation IPALoaderPicker
- (void)documentPickerWasCancelled:
    (UIDocumentPickerViewController *)controller {
  ipa_ios_dismiss(controller, ^{
    dispatch_semaphore_signal(self.done);
  });
}
- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
  @try {
    NSURL *url = urls.firstObject;
    if (!url) {
      self.failed = YES;
      return;
    }
    BOOL scoped = [url startAccessingSecurityScopedResource];
    @try {
      NSString *directory = [NSTemporaryDirectory()
          stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
      NSError *error = nil;
      [[NSFileManager defaultManager]
                createDirectoryAtPath:directory
          withIntermediateDirectories:YES
                           attributes:@{NSFilePosixPermissions : @0700}
                                error:&error];
      NSString *target =
          [directory stringByAppendingPathComponent:@"selected.ipa"];
      if (error || ![[NSFileManager defaultManager]
                       copyItemAtURL:url
                               toURL:[NSURL fileURLWithPath:target]
                               error:&error]) {
        self.failed = YES;
        return;
      }
      [[NSFileManager defaultManager]
          setAttributes:@{NSFilePosixPermissions : @0600}
           ofItemAtPath:target
                  error:nil];
      self.selected = strdup(target.fileSystemRepresentation);
    } @finally {
      if (scoped)
        [url stopAccessingSecurityScopedResource];
    }
  } @catch (NSException *e) {
    self.failed = YES;
  } @finally {
    ipa_ios_dismiss(controller, ^{
      dispatch_semaphore_signal(self.done);
    });
  }
}
@end
char *ipa_ios_choose(int *failed) {
  if (NSThread.isMainThread) {
    *failed = 1;
    return NULL;
  }
  IPALoaderPicker *delegate = [IPALoaderPicker new];
  delegate.done = dispatch_semaphore_create(0);
  dispatch_async(dispatch_get_main_queue(), ^{
    UIViewController *root = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
      if ([scene isKindOfClass:UIWindowScene.class]) {
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
          if (window.isKeyWindow) {
            root = window.rootViewController;
            break;
          }
        }
      }
    }
    if (!root) {
      for (UIWindow *window in UIApplication.sharedApplication.windows) {
        if (window.isKeyWindow) {
          root = window.rootViewController;
          break;
        }
      }
    }
    if (!root) {
      delegate.failed = YES;
      dispatch_semaphore_signal(delegate.done);
      return;
    }
    while (root.presentedViewController)
      root = root.presentedViewController;
    UTType *ipa = [UTType typeWithFilenameExtension:@"ipa"];
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc]
            initForOpeningContentTypes:@[ ipa ?: UTTypeData ]
                                asCopy:YES];
    picker.delegate = delegate;
    picker.allowsMultipleSelection = NO;
    [root presentViewController:picker animated:YES completion:nil];
  });
  dispatch_semaphore_wait(delegate.done, DISPATCH_TIME_FOREVER);
  *failed = delegate.failed ? 1 : 0;
  return delegate.selected;
}
static NSMutableSet<NSNumber *> *ipaTasks;
unsigned long ipa_ios_begin(void) {
  __block UIBackgroundTaskIdentifier task = UIBackgroundTaskInvalid;
  void (^begin)(void) = ^{
    if (!ipaTasks)
      ipaTasks = [NSMutableSet new];
    task = [UIApplication.sharedApplication
        beginBackgroundTaskWithName:@"Install IPA"
                  expirationHandler:^{
                    if ([ipaTasks containsObject:@(task)]) {
                      [ipaTasks removeObject:@(task)];
                      [UIApplication.sharedApplication endBackgroundTask:task];
                    }
                  }];
    if (task != UIBackgroundTaskInvalid)
      [ipaTasks addObject:@(task)];
  };
  if (NSThread.isMainThread)
    begin();
  else
    dispatch_sync(dispatch_get_main_queue(), begin);
  return (unsigned long)task;
}
void ipa_ios_end(unsigned long identifier) {
  dispatch_async(dispatch_get_main_queue(), ^{
    NSNumber *key = @(identifier);
    if ([ipaTasks containsObject:key]) {
      [ipaTasks removeObject:key];
      [UIApplication.sharedApplication
          endBackgroundTask:(UIBackgroundTaskIdentifier)identifier];
    }
  });
}
