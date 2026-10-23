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
static BOOL builtinVPN = YES;
static NSURL *openedURL;
static NSString *lastAction;
static NSDictionary *updateState;
@interface HarnessApplication : UIApplication
@end
@implementation HarnessApplication
- (void)openURL:(NSURL *)url
              options:(NSDictionary *)options
    completionHandler:(void (^)(BOOL))completion {
  openedURL = url;
  if (completion)
    completion(YES);
}
@end
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
  lastAction = action[@"Kind"];
  if ([action[@"Kind"] isEqual:@"import"])
    importRequests++;
  if ([action[@"Kind"] isEqual:@"connection"])
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      int failed = 0;
      free(ipa_ios_connection_settings(builtinVPN, "10.7.0.1", &failed));
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
    @"VPNAvailable" : @(builtinVPN),
    @"VPNConnected" : @(builtinVPN)
  };
  NSMutableDictionary *fullState = [state mutableCopy];
  if (updateState)
    [fullState addEntriesFromDictionary:updateState];
  NSData *data = [NSJSONSerialization dataWithJSONObject:fullState
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
// UIKit transitions can outlast a fixed delay on a busy CI simulator.
static void waitForUIUntil(BOOL (^ready)(void), dispatch_block_t check,
                           NSTimeInterval deadline) {
  if (ready()) {
    check();
    return;
  }
  NSCAssert(NSProcessInfo.processInfo.systemUptime < deadline,
            @"Timed out waiting for the UIKit transition");
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC),
                 dispatch_get_main_queue(), ^{
                   waitForUIUntil(ready, check, deadline);
                 });
}
static void waitForUI(BOOL (^ready)(void), dispatch_block_t check) {
  waitForUIUntil(ready, check, NSProcessInfo.processInfo.systemUptime + 10);
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
  } else if ([NSProcessInfo.processInfo.arguments
                 containsObject:@"--update-feedback-checks"]) {
    [self runUpdateFeedbackChecks];
  } else if ([NSProcessInfo.processInfo.arguments
                 containsObject:@"--update-checks"]) {
    [self runUpdateChecks];
  } else if ([NSProcessInfo.processInfo.arguments
                 containsObject:@"--connection-checks"]) {
    builtinVPN =
        ![NSProcessInfo.processInfo.arguments containsObject:@"--localdevvpn"];
    [self runConnectionChecks];
  } else
    [self runChecks];
  return YES;
}
- (void)runUpdateFeedbackChecks {
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        NSArray *cases = @[
          @{
            @"state" : @{@"UpdateCheckedAt" : @1234567890},
            @"title" : @"Up to Date",
            @"detail" : @"Last checked"
          },
          @{
            @"state" : @{@"UpdateCheckedAt" : @1234567891},
            @"title" : @"Up to Date",
            @"detail" : @"Last checked"
          },
          @{
            @"state" : @{
              @"UpdateCheckedAt" : @1234567892,
              @"UpdateVersion" : @"1.2.0"
            },
            @"title" : @"IPA Loader 1.2.0 Available",
            @"detail" : @"Last checked"
          },
          @{
            @"state" : @{
              @"UpdateCheckedAt" : @1234567893,
              @"UpdateCheckFailed" : @YES,
              @"UpdateMessage" : @"You are offline."
            },
            @"title" : @"Couldn’t Check for Updates",
            @"detail" : @"You are offline."
          },
          @{
            @"state" : @{@"UpdateChecking" : @YES},
            @"title" : @"Checking for Updates…",
            @"detail" : @"Checking GitHub"
          }
        ];
        for (NSDictionary *test in cases) {
          updateState = test[@"state"];
          publish(NO, NO, @"");
          dispatch_async(dispatch_get_main_queue(), ^{
            UINavigationController *nav =
                (UINavigationController *)ipaAccountNavigation;
            UITableViewController *settings =
                (UITableViewController *)nav.topViewController;
            ipaTabs.selectedIndex = 1;
            NSIndexPath *path = [NSIndexPath indexPathForRow:0 inSection:2];
            UITableViewCell *cell =
                [settings.tableView.dataSource tableView:settings.tableView
                                   cellForRowAtIndexPath:path];
            NSCAssert([cell.textLabel.text isEqual:test[@"title"]],
                      @"Update outcome is not visible beside the action");
            NSCAssert(
                [cell.detailTextLabel.text containsString:test[@"detail"]],
                @"Update detail missing");
            BOOL checking = [test[@"state"][@"UpdateChecking"] boolValue];
            NSCAssert([cell.accessoryView
                          isKindOfClass:UIActivityIndicatorView.class] ==
                          checking,
                      @"Checking indicator is incorrect");
            lastAction = nil;
            [settings.tableView.delegate tableView:settings.tableView
                           didSelectRowAtIndexPath:path];
            NSCAssert(checking ? lastAction == nil
                               : [lastAction isEqual:@"checkupdate"],
                      @"Result row cannot be checked again");
          });
        }
        dispatch_async(dispatch_get_main_queue(), ^{
          NSLog(@"PASS: update results persist beside the action with "
                @"timestamps, retry and checking feedback");
          exit(0);
        });
      });
}
- (void)runUpdateChecks {
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        ipaTabs.selectedIndex = 1;
        updateState = @{
          @"UpdateVersion" : @"1.2.0",
          @"UpdateMessage" : @"New release available"
        };
        publish(NO, NO, @"");
        dispatch_async(dispatch_get_main_queue(), ^{
          UINavigationController *nav =
              (UINavigationController *)ipaAccountNavigation;
          UITableViewController *settings =
              (UITableViewController *)nav.topViewController;
          NSIndexPath *check = [NSIndexPath indexPathForRow:0 inSection:2];
          NSIndexPath *install = [NSIndexPath indexPathForRow:1 inSection:2];
          NSCAssert([settings.tableView.dataSource tableView:settings.tableView
                                       numberOfRowsInSection:2] == 2,
                    @"Update rows missing");
          UITableViewCell *cell =
              [settings.tableView.dataSource tableView:settings.tableView
                                 cellForRowAtIndexPath:install];
          NSCAssert(
              [cell.textLabel.text isEqual:@"Download and Install Update"],
              @"Update button missing");
          lastAction = nil;
          [settings.tableView.delegate tableView:settings.tableView
                         didSelectRowAtIndexPath:install];
          NSCAssert(lastAction == nil, @"Signed-out update allowed");
          [settings.tableView.delegate tableView:settings.tableView
                         didSelectRowAtIndexPath:check];
          NSCAssert([lastAction isEqual:@"checkupdate"],
                    @"Check action missing");
          NSCAssert([nav.tabBarItem.badgeValue isEqual:@"1"],
                    @"Available update badge missing");
          updateState = @{@"UpdateVersion" : @"1.2.0", @"VPNConnected" : @NO};
          publish(YES, NO, @"");
          dispatch_async(dispatch_get_main_queue(), ^{
            ipaTabs.selectedIndex = 1;
            lastAction = nil;
            [settings.tableView.delegate tableView:settings.tableView
                           didSelectRowAtIndexPath:install];
            NSCAssert(lastAction == nil,
                      @"Update allowed with built-in VPN off");
            updateState = @{@"UpdateVersion" : @"1.2.0"};
            publish(YES, NO, @"");
            dispatch_async(dispatch_get_main_queue(), ^{
              [settings.tableView.delegate tableView:settings.tableView
                             didSelectRowAtIndexPath:install];
              NSCAssert([lastAction isEqual:@"update"],
                        @"Update action missing");
              updateState =
                  @{@"UpdateVersion" : @"1.2.0", @"Operation" : @"update"};
              publish(YES, YES, @"Downloading IPA Loader…");
            });
          });
        });
      });
  waitForUI(
      ^BOOL {
        UINavigationController *sheet =
            (UINavigationController *)ipaTabs.presentedViewController;
        return [sheet isKindOfClass:UINavigationController.class] &&
               [sheet.topViewController.title isEqual:@"Update IPA Loader"] &&
               sheet.topViewController.view.window != nil;
      },
      ^{
        NSCAssert(ipaTabs.selectedIndex == 1, @"Update left Settings tab");
        NSLog(@"PASS: update discovery, account and VPN gating, actions and "
              @"progress from Settings");
        exit(0);
      });
}
- (void)runConnectionChecks {
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
      dispatch_get_main_queue(), ^{
        UINavigationController *accountNavigation =
            (UINavigationController *)ipaAccountNavigation;
        UITableViewController *account =
            (UITableViewController *)accountNavigation.topViewController;
        // Exercise both authenticated layouts: no toggle or certificate rows
        // may leak into the external variant when its account state changes.
        for (NSNumber *signedIn in @[ @NO, @YES ]) {
          publish(signedIn.boolValue, NO, @"");
          dispatch_async(dispatch_get_main_queue(), ^{
            NSInteger rows =
                [account.tableView.dataSource tableView:account.tableView
                                  numberOfRowsInSection:1];
            NSCAssert(rows == (signedIn.boolValue ? 3 : 2),
                      @"Connection row count changed");
            for (NSInteger row = 0; row < rows; row++) {
              UITableViewCell *cell = [account.tableView.dataSource
                              tableView:account.tableView
                  cellForRowAtIndexPath:[NSIndexPath indexPathForRow:row
                                                           inSection:1]];
              BOOL toggle = [cell.accessoryView isKindOfClass:UISwitch.class];
              NSCAssert(toggle == (builtinVPN && row == 0),
                        @"Wrong variant shows a VPN toggle");
              if (toggle) {
                UISwitch *control = (UISwitch *)cell.accessoryView;
                NSCAssert(control.on && control.enabled,
                          @"Built-in VPN toggle lost its state");
              }
              NSString *title =
                  row == 2
                      ? @"Certificates"
                      : (builtinVPN
                             ? (row == 0 ? @"Local VPN" : @"Connection Help")
                             : (row == 0 ? @"Connection Settings"
                                         : @"Get LocalDevVPN"));
              NSCAssert([cell.textLabel.text isEqual:title],
                        @"Connection row title is incorrect");
            }
            NSString *footer =
                [account.tableView.dataSource tableView:account.tableView
                                titleForFooterInSection:1];
            NSCAssert([footer containsString:builtinVPN ? @"Local VPN"
                                                        : @"LocalDevVPN"],
                      @"Connection footer uses wrong variant");
            NSCAssert(builtinVPN || (![footer containsString:@"Local VPN"] &&
                                     [footer containsString:@"Device IP"]),
                      @"External footer refers to built-in controls");
          });
        }
        dispatch_async(dispatch_get_main_queue(), ^{
          ipaTabs.selectedIndex = 1;
          if (!builtinVPN) {
            [account.tableView.delegate
                              tableView:account.tableView
                didSelectRowAtIndexPath:[NSIndexPath indexPathForRow:1
                                                           inSection:1]];
            NSCAssert(
                [openedURL.absoluteString
                    isEqual:@"https://apps.apple.com/app/id6755608044"],
                @"Main Settings does not open LocalDevVPN's App Store page");
            openedURL = nil;
          }
          [account.tableView.delegate
                            tableView:account.tableView
              didSelectRowAtIndexPath:[NSIndexPath indexPathForRow:2
                                                         inSection:1]];
          [accountNavigation.topViewController loadViewIfNeeded];
          NSCAssert([lastAction isEqual:@"certificates"] &&
                        [accountNavigation.topViewController.title
                            isEqual:@"Certificates"],
                    @"Certificate row routed to the wrong action");
          [accountNavigation popToRootViewControllerAnimated:NO];
          [account.tableView.delegate
                            tableView:account.tableView
              didSelectRowAtIndexPath:[NSIndexPath
                                          indexPathForRow:builtinVPN ? 1 : 0
                                                inSection:1]];
          NSCAssert([lastAction isEqual:@"connection"],
                    @"Connection row routed to the wrong action");
        });
      });
  waitForUI(
      ^BOOL {
        UINavigationController *nav =
            (UINavigationController *)ipaTabs.presentedViewController;
        return [nav isKindOfClass:UINavigationController.class] &&
               nav.topViewController.view.window != nil;
      },
      ^{
        UINavigationController *nav =
            (UINavigationController *)ipaTabs.presentedViewController;
        UITableViewController *settings =
            (UITableViewController *)nav.topViewController;
        NSCAssert([settings.title isEqual:builtinVPN ? @"Connection Help"
                                                     : @"Connection Settings"],
                  @"Wrong connection sheet");
        NSInteger rows =
            [settings.tableView.dataSource tableView:settings.tableView
                               numberOfRowsInSection:0];
        NSCAssert(rows == (builtinVPN ? 1 : 3),
                  @"Connection sheet has wrong variant's controls");
        UITableViewCell *help = [settings.tableView.dataSource
                        tableView:settings.tableView
            cellForRowAtIndexPath:[NSIndexPath indexPathForRow:0 inSection:0]];
        NSCAssert([help.textLabel.text containsString:builtinVPN
                                                          ? @"Local VPN switch"
                                                          : @"LocalDevVPN"],
                  @"Connection sheet guidance is incorrect");
        if (!builtinVPN) {
          NSCAssert(![help.textLabel.text containsString:@"Local VPN"] &&
                        [help.textLabel.text containsString:@"refresh"],
                    @"External connection sheet mentions built-in controls");
          UITableViewCell *ip = [settings.tableView.dataSource
                          tableView:settings.tableView
              cellForRowAtIndexPath:[NSIndexPath indexPathForRow:1
                                                       inSection:0]];
          NSCAssert([ip.textLabel.text isEqual:@"Device IP"] &&
                        [ip.accessoryView isKindOfClass:UITextField.class],
                    @"LocalDevVPN Device IP field is missing");
          UITableViewCell *store = [settings.tableView.dataSource
                          tableView:settings.tableView
              cellForRowAtIndexPath:[NSIndexPath indexPathForRow:2
                                                       inSection:0]];
          NSCAssert([store.textLabel.text isEqual:@"Get LocalDevVPN"],
                    @"LocalDevVPN App Store link is missing");
          [settings.tableView.delegate
                            tableView:settings.tableView
              didSelectRowAtIndexPath:[NSIndexPath indexPathForRow:2
                                                         inSection:0]];
          NSCAssert([openedURL.absoluteString
                        isEqual:@"https://apps.apple.com/app/id6755608044"],
                    @"Connection sheet opens the wrong App Store page");
        }
        NSLog(
            @"PASS: %@ connection controls, copy, routing and App Store links",
            builtinVPN ? @"built-in VPN" : @"LocalDevVPN");
        exit(0);
      });
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
                                    numberOfRowsInSection:2] == 1,
                  @"Check for Updates row missing");
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
        NSLog(@"PASS: validated account enables refresh without leaving Apps");
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
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4200 * NSEC_PER_MSEC),
                 dispatch_get_main_queue(), ^{
                   waitForUI(
                       ^BOOL {
                         return ipaProgress.navigationController
                                    .presentingViewController != nil;
                       },
                       ^{
                         cancelledOperation = YES;
                         publish(YES, NO, @"");
                         waitForUI(
                             ^BOOL {
                               return !ipaProgress.navigationController
                                           .presentingViewController &&
                                      ipaApps.tableView.tableHeaderView == nil;
                             },
                             ^{
                               NSLog(@"PASS: cancellation quietly dismisses "
                                     @"the progress sheet");
                               exit(0);
                             });
                       });
                 });
}
@end
int main(int argc, char **argv) {
  @autoreleasepool {
    return UIApplicationMain(argc, argv,
                             NSStringFromClass(HarnessApplication.class),
                             NSStringFromClass(AppsHarness.class));
  }
}
