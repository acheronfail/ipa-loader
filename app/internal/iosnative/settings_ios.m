//go:build ios
#import "controls_ios.h"
#import <UIKit/UIKit.h>
#include <stdlib.h>
#include <string.h>

void ipa_ios_open_localdevvpn(void) {
  [UIApplication.sharedApplication
                openURL:[NSURL URLWithString:
                                   @"https://apps.apple.com/app/id6755608044"]
                options:@{}
      completionHandler:nil];
}

@interface IPALoaderConnectionSettings
    : UITableViewController <UIAdaptivePresentationControllerDelegate>
@property(nonatomic) BOOL builtin;
@property(nonatomic, copy) NSString *status;
@property(nonatomic) UITextField *address;
@property(nonatomic) BOOL finished;
@property(nonatomic) char *result;
@property(nonatomic) dispatch_semaphore_t done;
@end
@implementation IPALoaderConnectionSettings
- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = self.builtin ? @"Connection Help" : @"Connection Settings";
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 72;
  self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
  if (self.builtin) {
    self.navigationItem.rightBarButtonItem =
        ipa_ios_bar_button(@"Done", self, @selector(cancel), NO);
  } else {
    self.navigationItem.leftBarButtonItem =
        ipa_ios_bar_button(@"Cancel", self, @selector(cancel), NO);
    self.navigationItem.rightBarButtonItem =
        ipa_ios_bar_button(@"Save", self, @selector(save), YES);
  }
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return 1;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  return self.builtin ? 1 : 3;
}
- (NSString *)tableView:(UITableView *)tableView
    titleForHeaderInSection:(NSInteger)section {
  return self.builtin ? @"Local VPN" : @"LocalDevVPN";
}
- (CGFloat)tableView:(UITableView *)tableView
    heightForRowAtIndexPath:(NSIndexPath *)path {
  if (path.section == 0 && !self.builtin && path.row == 1)
    return 64;
  return UITableViewAutomaticDimension;
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  // There are at most five rows. Fresh cells avoid carrying
  // action/accessibility traits between descriptive text, status, and the
  // editable IP address.
  UITableViewCell *cell =
      [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                             reuseIdentifier:nil];
  cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
  cell.textLabel.adjustsFontForContentSizeCategory = YES;
  cell.textLabel.numberOfLines = 0;
  cell.selectionStyle = UITableViewCellSelectionStyleNone;
  if (path.row == 0) {
    cell.textLabel.text = self.status;
  } else if (path.row == 1) {
    cell.textLabel.text = @"Device IP";
    cell.accessoryView = self.address;
  } else {
    cell.textLabel.text = @"Get LocalDevVPN";
    cell.textLabel.textColor = self.view.tintColor;
    cell.accessibilityTraits = UIAccessibilityTraitButton;
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;
  }
  return cell;
}
- (void)tableView:(UITableView *)tableView
    didSelectRowAtIndexPath:(NSIndexPath *)path {
  [tableView deselectRowAtIndexPath:path animated:YES];
  if (path.section != 0)
    return;
  if (!self.builtin && path.row == 2) {
    ipa_ios_open_localdevvpn();
  }
}
- (void)finish {
  if (self.finished)
    return;
  self.finished = YES;
  dispatch_semaphore_signal(self.done);
}
- (void)cancel {
  [self dismissViewControllerAnimated:YES
                           completion:^{
                             [self finish];
                           }];
}
- (void)save {
  [self.view endEditing:YES];
  self.result = strdup((self.address.text ?: @"").UTF8String);
  [self dismissViewControllerAnimated:YES
                           completion:^{
                             [self finish];
                           }];
}
- (void)presentationControllerDidDismiss:
    (UIPresentationController *)controller {
  [self finish];
}
@end

char *ipa_ios_connection_settings(int builtin, const char *address,
                                  int *failed) {
  if (NSThread.isMainThread) {
    *failed = 1;
    return NULL;
  }
  @autoreleasepool {
    __block IPALoaderConnectionSettings *settings = nil;
    dispatch_semaphore_t ready = dispatch_semaphore_create(0);
    NSString *ip = @(address);
    dispatch_async(dispatch_get_main_queue(), ^{
      UIViewController *root = nil;
      for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (scene.activationState != UISceneActivationStateForegroundActive ||
            ![scene isKindOfClass:UIWindowScene.class])
          continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows)
          if (window.isKeyWindow) {
            root = window.rootViewController;
            break;
          }
        if (root)
          break;
      }
      // The app owns its window through the application delegate.
      if (!root) {
        id<UIApplicationDelegate> delegate =
            UIApplication.sharedApplication.delegate;
        if ([delegate respondsToSelector:@selector(window)])
          root = delegate.window.rootViewController;
      }
      if (!root) {
        dispatch_semaphore_signal(ready);
        return;
      }
      while (root.presentedViewController)
        root = root.presentedViewController;
      [root.view endEditing:YES];
      settings = [[IPALoaderConnectionSettings alloc]
          initWithStyle:UITableViewStyleInsetGrouped];
      settings.builtin = builtin;
      settings.done = dispatch_semaphore_create(0);
      settings.status =
          builtin
              ? @"Use the Local VPN switch in Settings to connect this "
                @"iPhone. Disconnect other VPN apps first. IPA Loader "
                @"leaves the VPN off until you enable it."
              : @"Get LocalDevVPN from the App Store using the link below, "
                @"then connect it and use Wi-Fi to install, refresh, and "
                @"check apps. Enter the Device IP shown in LocalDevVPN below.";
      settings.address =
          [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 180, 44)];
      settings.address.text = ip;
      settings.address.textAlignment = NSTextAlignmentRight;
      settings.address.font =
          [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
      settings.address.adjustsFontForContentSizeCategory = YES;
      settings.address.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
      settings.address.autocorrectionType = UITextAutocorrectionTypeNo;
      settings.address.autocapitalizationType =
          UITextAutocapitalizationTypeNone;
      settings.address.accessibilityLabel = @"Device IP";
      UINavigationController *navigation =
          [[UINavigationController alloc] initWithRootViewController:settings];
      navigation.modalPresentationStyle = UIModalPresentationPageSheet;
      if (@available(iOS 15.0, *)) {
        navigation.sheetPresentationController.detents =
            @[ UISheetPresentationControllerDetent.largeDetent ];
        navigation.sheetPresentationController.prefersGrabberVisible = YES;
      }
      navigation.presentationController.delegate = settings;
      [root presentViewController:navigation animated:YES completion:nil];
      dispatch_semaphore_signal(ready);
    });
    dispatch_semaphore_wait(ready, DISPATCH_TIME_FOREVER);
    if (!settings) {
      *failed = 1;
      return NULL;
    }
    dispatch_semaphore_wait(settings.done, DISPATCH_TIME_FOREVER);
    return settings.result;
  }
}
