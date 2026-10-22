// Production UIKit screens in a disposable simulator app. No Apple credentials,
// signing, VPN or physical-device operations are used.
#import "../apps_ios.m"
#import <UIKit/UIKit.h>

static NSInteger inventoryReads, refreshRequests, importRequests;
static BOOL importReturned, importAccepted;
extern int ipa_ios_confirm_import(const char *json);
extern char *ipa_ios_connection_settings(int builtin, const char *address,
                                         int *failed);
static NSDictionary *sample;
static NSArray *previewLogs;
static NSInteger operationIdentity = 1;
static BOOL cancelledOperation;
extern void ipa_ios_shell_update(const char *json);
void ipa_go_apps_load(int check) {
  inventoryReads++;
  NSData *data = [NSJSONSerialization dataWithJSONObject:@{
    @"Apps" : @[ sample ],
    @"Message" : @""
  }
                                                 options:0
                                                   error:nil];
  ipa_ios_apps_update([[NSString alloc] initWithData:data
                                            encoding:NSUTF8StringEncoding]
                          .UTF8String);
}
void ipa_go_apps_action(char *bundle) { refreshRequests++; }
void ipa_go_shell_started(void) {}
void ipa_go_shell_action(char *json) {
  NSDictionary *action = [NSJSONSerialization
      JSONObjectWithData:[@(json) dataUsingEncoding:NSUTF8StringEncoding]
                 options:0
                   error:nil];
  if ([action[@"Kind"] isEqual:@"import"])
    importRequests++;
  if ([action[@"Kind"] isEqual:@"connection"])
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      int failed = 0;
      free(ipa_ios_connection_settings(1, "10.7.0.1", &failed));
    });
}
static void publish(BOOL signedIn, BOOL busy, NSString *message) {
  NSDictionary *state = @{
    @"Authenticated" : @(signedIn),
    @"Busy" : @(busy),
    @"Username" : @"owner@example.invalid",
    @"AccountMessage" : @"",
    @"Accounts" : @[ @"owner@example.invalid" ],
    @"Teams" : @[ @{@"ID" : @"TEAM", @"Name" : @"Personal"} ],
    @"TeamID" : @"TEAM",
    @"Quota" : @"10 App IDs",
    @"Certificates" : @[ @{
      @"Name" : @"Apple Development: IPA Loader",
      @"Kind" : @"Apple Development",
      @"IssuedAt" : @"2026-10-20T00:00:00Z",
      @"ExpiresAt" : @"2027-10-20T00:00:00Z",
      @"Serial" : @"123456789",
      @"SHA256" : @"preview-only"
    } ],
    @"Operation" : @"refresh",
    @"Target" : @"org.example.sample",
    @"Message" : message,
    @"Fraction" : @0.5,
    @"Logs" : previewLogs ?: @[ message ],
    @"OperationID" : @(operationIdentity),
    @"Cancelled" : @(cancelledOperation),
    @"EligibleRefreshes" : @1,
    @"VPNAvailable" : @YES,
    @"VPNConnected" : @YES
  };
  NSData *data = [NSJSONSerialization dataWithJSONObject:state
                                                 options:0
                                                   error:nil];
  ipa_ios_apps_authenticated(signedIn);
  ipa_ios_apps_busy(busy);
  ipa_ios_shell_update([[NSString alloc] initWithData:data
                                             encoding:NSUTF8StringEncoding]
                           .UTF8String);
}
static NSString *importJSON(void) {
  UIGraphicsImageRenderer *renderer =
      [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(1024, 1024)];
  UIImage *image =
      [renderer imageWithActions:^(UIGraphicsImageRendererContext *context) {
        [UIColor.systemTealColor setFill];
        UIRectFill(CGRectMake(0, 0, 1024, 1024));
      }];
  if ([NSProcessInfo.processInfo.arguments containsObject:@"--preview"])
    image = [UIImage imageNamed:@"AppIcon180"] ?: image;
  NSDictionary *info = @{
    @"Name" : @"Sample App",
    @"BundleID" : @"org.ipaloader.sample",
    @"Version" : @"1.0",
    @"Build" : @"15",
    @"Size" : @(3LL << 30),
    @"Icon" : [UIImagePNGRepresentation(image) base64EncodedStringWithOptions:0]
  };
  NSData *data = [NSJSONSerialization dataWithJSONObject:info
                                                 options:0
                                                   error:nil];
  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}
static UIImageView *findIcon(UIView *view) {
  if ([view isKindOfClass:UIImageView.class])
    return (UIImageView *)view;
  for (UIView *child in view.subviews) {
    UIImageView *icon = findIcon(child);
    if (icon)
      return icon;
  }
  return nil;
}
static UIButton *findButton(UIView *view) {
  if ([view isKindOfClass:UIButton.class])
    return (UIButton *)view;
  for (UIView *child in view.subviews) {
    UIButton *button = findButton(child);
    if (button)
      return button;
  }
  return nil;
}
static UIButton *rowButton(void) {
  UITableViewCell *cell = [ipaApps tableView:ipaApps.tableView
                       cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0
                                                                inSection:0]];
  return findButton(cell.contentView);
}
static NSInteger appsReloads, settingsReloads;
static UIBarButtonItem *stableImportButton;
@interface CountingTable : UITableView
@end
@implementation CountingTable
- (void)reloadData {
  if (self.tag == 1)
    appsReloads++;
  else
    settingsReloads++;
  [super reloadData];
}
@end
static void trackReloads(UITableViewController *controller, NSInteger tag) {
  CountingTable *table =
      [[CountingTable alloc] initWithFrame:controller.tableView.frame
                                     style:UITableViewStyleInsetGrouped];
  table.tag = tag;
  table.dataSource = controller;
  table.delegate = controller;
  controller.tableView = table;
}
@interface AppsHarness : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation AppsHarness
- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)options {
  [UIView setAnimationsEnabled:NO];
  sample = @{
    @"BundleID" : @"org.example.sample",
    @"Name" : @"Sample",
    @"Account" : @"owner@example.invalid",
    @"Expires" : @"2026-10-28T00:00:00Z",
    @"Refreshed" : @"2026-10-21T00:00:00Z",
    @"Icon" : NSNull.null
  };
  self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
  self.window.rootViewController = ipa_ios_make_root();
  [self.window makeKeyAndVisible];
  if ([NSProcessInfo.processInfo.arguments containsObject:@"--preview"]) {
    if ([NSProcessInfo.processInfo.arguments containsObject:@"--dark"])
      self.window.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    publish(YES, NO, @"");
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 400 * NSEC_PER_MSEC),
        dispatch_get_main_queue(), ^{
          ipaVPNRequired = YES;
          ipaVPNConnected = YES;
          [ipaApps updateControls];
          if ([NSProcessInfo.processInfo.arguments
                  containsObject:@"--details"]) {
            previewLogs = @[
              @"Connecting to this iPhone…", @"Checking IPA compatibility",
              @"Reading target iPhone identity", @"Resolving app identity",
              @"Preparing account signing material with the team-suffixed app identifier",
              @"Checking saved signing identities",
              @"Signing app and embedded frameworks", @"Staging app files",
              @"Installing app", @"Checking installed version and build",
              @"Installation confirmed"
            ];
            publish(YES, NO, @"App installed.");
            dispatch_after(
                dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
                dispatch_get_main_queue(), ^{
                  [ipaProgress toggleDetails];
                });
          }
          if ([NSProcessInfo.processInfo.arguments containsObject:@"--review"])
            dispatch_async(
                dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                  ipa_ios_confirm_import(importJSON().UTF8String);
                });
          if ([NSProcessInfo.processInfo.arguments
                  containsObject:@"--progress"])
            publish(YES, YES, @"1 of 2 · Sample\nChecking signing profile…");
        });
  } else
    [self runChecks];
  return YES;
}
- (void)runChecks {
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(self.window.rootViewController == ipaTabs &&
                      ipaTabs.selectedIndex == 0 &&
                      ipaTabs.viewControllers.count == 2,
                  @"Apps is not the signed-out home");
        NSCAssert([ipaAccountNavigation.tabBarItem.title isEqual:@"Settings"],
                  @"Account tab is unstable");
        NSCAssert(inventoryReads > 0 && ipaApps.apps.count == 1,
                  @"Signed-out inventory missing");
        NSCAssert(!rowButton().enabled &&
                      !ipaApps.navigationItem.leftBarButtonItem.enabled,
                  @"Signed-out signing actions enabled");
        [ipaApps refreshApp:sample];
        NSCAssert(refreshRequests == 0, @"Signed-out refresh reached backend");
        [ipaApps showDetails:sample];
        NSCAssert([ipaApps.navigationController.topViewController
                      isKindOfClass:IPALoaderAppDetails.class],
                  @"Signed-out details unavailable");
        [ipaApps.navigationController popToRootViewControllerAnimated:NO];
        NSLog(
            @"PASS: signed-out app list, account details and disabled actions");
        NSCAssert([ipaTabs.viewControllers.firstObject.tabBarItem.title
                      isEqual:@"Apps"],
                  @"Apps tab title incorrect");
        ipaTabs.selectedIndex = 1;
        publish(YES, NO, @"");
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(ipaTabs.selectedIndex == 0 && rowButton().enabled &&
                      ipaApps.navigationItem.leftBarButtonItem.enabled,
                  @"Validated account did not enable Apps");
        UITableViewController *account =
            (UITableViewController *)((UINavigationController *)
                                          ipaAccountNavigation)
                .topViewController;
        NSCAssert([account.tableView.dataSource tableView:account.tableView
                                    numberOfRowsInSection:0] == 3,
                  @"Native account state missing");
        UITableViewCell *teamCell = [account.tableView.dataSource
                        tableView:account.tableView
            cellForRowAtIndexPath:[NSIndexPath indexPathForRow:1 inSection:0]];
        NSCAssert(teamCell.accessoryType == UITableViewCellAccessoryNone &&
                      teamCell.selectionStyle ==
                          UITableViewCellSelectionStyleNone,
                  @"Single developer team looks interactive");
        [account.tableView.delegate tableView:account.tableView
                      didSelectRowAtIndexPath:[NSIndexPath indexPathForRow:1
                                                                 inSection:0]];
        NSCAssert(!account.presentedViewController,
                  @"Single developer team opened a picker");
        NSCAssert([account.tableView.dataSource tableView:account.tableView
                                    numberOfRowsInSection:2] == 0,
                  @"About row remains");
        NSCAssert([[account.tableView.dataSource tableView:account.tableView
                                   titleForFooterInSection:2]
                      containsString:@"IPA Loader"],
                  @"Version footer disappeared");
        trackReloads(ipaApps, 1);
        trackReloads(account, 2);
        [ipaApps refreshApp:sample];
        NSCAssert(ipaTabs.selectedIndex == 0 && refreshRequests == 1,
                  @"Refresh changed tabs or missed backend");
        [ipaApps refreshApp:sample];
        NSCAssert(refreshRequests == 1,
                  @"Immediate duplicate refresh accepted");
        publish(YES, YES, @"Applying profiles");
        NSLog(
            @"PASS: validated account enables refresh without leaving Apps");
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 1000 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(
            ipaApps.tableView.tableHeaderView == nil &&
                ipaProgress.navigationController.presentingViewController !=
                    nil,
            @"Progress sheet missing or old panel retained");
        NSCAssert(!rowButton().enabled &&
                      rowButton().configuration.showsActivityIndicator,
                  @"Active app spinner missing");
        NSCAssert(!ipaApps.navigationItem.leftBarButtonItem.enabled,
                  @"Import allowed during refresh");
        [ipaApps refreshApp:sample];
        NSCAssert(refreshRequests == 1, @"Busy refresh reached backend");
        stableImportButton = ipaApps.navigationItem.leftBarButtonItem;
        appsReloads = settingsReloads = 0;
        publish(YES, YES, @"Checking expiry");
        publish(YES, YES, @"Checking expiry");
      });
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1400 * NSEC_PER_MSEC),
                 dispatch_get_main_queue(), ^{
                   NSCAssert(appsReloads == 0 && settingsReloads == 0,
                             @"Progress updates rebuilt scrolling tables");
                   NSCAssert(stableImportButton ==
                                 ipaApps.navigationItem.leftBarButtonItem,
                             @"Progress updates replaced the import button");
                   NSLog(@"PASS: repeated state and progress updates preserve "
                         @"table cells and navigation controls");
                   publish(YES, NO, @"App refreshed without reinstalling");
                 });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 1600 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(ipaTabs.selectedIndex == 0 && rowButton().enabled &&
                      !rowButton().configuration.showsActivityIndicator,
                  @"Completion changed navigation or left spinner");
        NSCAssert(ipaProgress.message.text.length > 0 &&
                      !ipaProgress.navigationController.modalInPresentation,
                  @"Completion result vanished or sheet cannot dismiss");
        [ipaProgress toggleDetails];
        [ipaProgress.view layoutIfNeeded];
        NSCAssert(!ipaProgress.logs.scrollEnabled && !ipaProgress.logs.hidden,
                  @"Details still use nested scrolling");
        for (NSLayoutConstraint *constraint in ipaProgress.logs.constraints)
          NSCAssert(constraint.firstAttribute != NSLayoutAttributeHeight ||
                        constraint.secondItem != nil || !constraint.active ||
                        fabs(constraint.constant - 160) > 0.5,
                    @"Details still have a fixed height");
        NSCAssert(ipaProgress.details.configuration.background != nil,
                  @"Details disclosure is not styled as a button");
        [ipaProgress finish];
        publish(NO, NO, @"App refreshed without reinstalling");
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 1800 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(self.window.rootViewController == ipaTabs &&
                      ipaApps.apps.count == 1 && !rowButton().enabled,
                  @"Account switch lost history or allowed signing");
        [ipaApps refreshApp:sample];
        NSCAssert(refreshRequests == 1, @"Signed-out refresh reached backend");
        NSLog(@"PASS: busy and signed-out actions blocked; app history remains "
              @"visible");
        publish(YES, NO, @"");
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 2200 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(rowButton().enabled &&
                      self.window.rootViewController == ipaTabs,
                  @"Repeated sign-in lost navigation");
        ipaVPNRequired = YES;
        ipaVPNConnected = NO;
        [ipaApps updateControls];
        NSCAssert(!rowButton().enabled &&
                      !ipaApps.navigationItem.leftBarButtonItem.enabled &&
                      !ipaApps.navigationItem.rightBarButtonItem.enabled,
                  @"VPN off did not disable app actions");
        [ipaApps refreshApp:sample];
        NSCAssert(refreshRequests == 1, @"VPN off reached backend");
        ipaVPNConnected = YES;
        [ipaApps updateControls];
        NSCAssert(rowButton().enabled &&
                      ipaApps.navigationItem.rightBarButtonItem.enabled,
                  @"VPN on did not enable app actions");
        [ipaApps importApp];
        NSCAssert(importRequests == 1 && ipaTabs.selectedIndex == 0,
                  @"Import did not start from Apps");
        NSLog(@"PASS: repeated sign-in restores actions without "
              @"replacing the tab hierarchy");
        dispatch_async(
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
              int accepted = ipa_ios_confirm_import(importJSON().UTF8String);
              dispatch_async(dispatch_get_main_queue(), ^{
                importAccepted = accepted != 0;
                importReturned = YES;
              });
            });
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 2600 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        UINavigationController *nav =
            (UINavigationController *)ipaTabs.presentedViewController;
        NSCAssert([nav.topViewController.title isEqual:@"Install App"],
                  @"Native import review did not open");
        UITableViewController *review =
            (UITableViewController *)nav.topViewController;
        UITableViewCell *identity = [review.tableView.dataSource
                        tableView:review.tableView
            cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0]];
        identity.frame = CGRectMake(0, 0, 340, 88);
        [identity layoutIfNeeded];
        UIImageView *icon = findIcon(identity.contentView);
        NSCAssert(icon && fabs(icon.bounds.size.width - 56) < 1 &&
                      fabs(icon.bounds.size.height - 56) < 1 &&
                      icon.clipsToBounds && icon.layer.cornerRadius > 10,
                  @"Large source icon was not constrained and rounded");
        NSCAssert([review.tableView.dataSource
                      numberOfSectionsInTableView:review.tableView] == 2,
                  @"Storage choice has no separate section");
        UITableViewCell *storage = [review.tableView.dataSource
                        tableView:review.tableView
            cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:1]];
        UISwitch *keep = (UISwitch *)storage.accessoryView;
        NSCAssert([keep isKindOfClass:UISwitch.class] && !keep.on,
                  @"IPA retention is not opt-in");
        keep.on = YES;
        [keep sendActionsForControlEvents:UIControlEventValueChanged];
        UIButton *cancel = (UIButton *)nav.topViewController.navigationItem
                               .leftBarButtonItem.customView;
        [cancel sendActionsForControlEvents:UIControlEventTouchUpInside];
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 3000 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(importReturned && !importAccepted &&
                      !ipaTabs.presentedViewController,
                  @"Import review cancellation did not finish cleanly");
        NSLog(@"PASS: native import review cancels before any signing");
        publish(YES, NO, @"");
      });
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3400 * NSEC_PER_MSEC),
                 dispatch_get_main_queue(), ^{
                   ipaTabs.selectedIndex = 1;
                   UITableViewController *account =
                       (UITableViewController *)((UINavigationController *)
                                                     ipaAccountNavigation)
                           .topViewController;
                   [account.tableView.delegate
                                     tableView:account.tableView
                       didSelectRowAtIndexPath:[NSIndexPath indexPathForRow:2
                                                                  inSection:0]];
                 });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 3800 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        UITableViewController *account =
            (UITableViewController *)((UINavigationController *)
                                          ipaAccountNavigation)
                .topViewController;
        UIAlertController *menu =
            (UIAlertController *)account.presentedViewController;
        NSCAssert([menu isKindOfClass:UIAlertController.class] &&
                      menu.preferredStyle == UIAlertControllerStyleActionSheet,
                  @"Switch Account did not open a native menu");
        NSArray *titles = [menu.actions valueForKey:@"title"];
        NSCAssert([titles containsObject:@"Add Another Account"] &&
                      [titles containsObject:@"Manage Accounts"] &&
                      [titles containsObject:@"Sign Out"],
                  @"Account management actions are missing");
        NSCAssert([account.tableView.dataSource tableView:account.tableView
                                    numberOfRowsInSection:0] == 3,
                  @"Opening account menu changed account rows");
        NSLog(@"PASS: native account menu preserves account rows and offers "
              @"add, manage and sign out");
        [account dismissViewControllerAnimated:NO
                                    completion:^{
                                      ipaTabs.selectedIndex = 0;
                                      operationIdentity = 2;
                                      publish(YES, YES,
                                              @"Connecting to this iPhone…");
                                    }];
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 4200 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(ipaProgress.navigationController.presentingViewController !=
                      nil,
                  @"Cancellation test progress did not open");
        cancelledOperation = YES;
        publish(YES, NO, @"");
      });
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 4600 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSCAssert(!ipaProgress.navigationController.presentingViewController &&
                      ipaApps.tableView.tableHeaderView == nil,
                  @"Cancelled operation left a progress/error sheet");
        NSLog(@"PASS: cancellation quietly dismisses the progress sheet");
        exit(0);
      });
}
@end
int main(int argc, char **argv) {
  @autoreleasepool {
    return UIApplicationMain(argc, argv, nil,
                             NSStringFromClass(AppsHarness.class));
  }
}
