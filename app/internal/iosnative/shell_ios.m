//go:build ios
#import "shell_ios.h"
#import "controls_ios.h"
#import <NetworkExtension/NetworkExtension.h>
#import <UIKit/UIKit.h>
#include <stdlib.h>
#include <string.h>
extern void ipa_go_shell_started(void);
extern void ipa_go_shell_action(char *json);
static NSDictionary *ipaShellState;
static UIViewController *ipaTopController(void) {
  UIViewController *root = nil;
  for (UIScene *scene in UIApplication.sharedApplication.connectedScenes)
    if ([scene isKindOfClass:UIWindowScene.class])
      for (UIWindow *window in ((UIWindowScene *)scene).windows)
        if (window.isKeyWindow)
          root = window.rootViewController;
  // The app owns its window through the application delegate.
  if (!root) {
    id<UIApplicationDelegate> delegate = UIApplication.sharedApplication.delegate;
    if ([delegate respondsToSelector:@selector(window)])
      root = delegate.window.rootViewController;
  }
  while (root.presentedViewController)
    root = root.presentedViewController;
  return root;
}
static void ipaSend(NSDictionary *action) {
  NSData *data = [NSJSONSerialization dataWithJSONObject:action
                                                 options:0
                                                   error:nil];
  if (data)
    ipa_go_shell_action((char *)[[[NSString alloc]
        initWithData:data
            encoding:NSUTF8StringEncoding] UTF8String]);
}
static UITableViewCell *ipaTextCell(NSString *title, NSString *detail,
                                    BOOL action, BOOL enabled) {
  UITableViewCell *cell =
      [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                             reuseIdentifier:nil];
  cell.textLabel.text = title;
  cell.detailTextLabel.text = detail;
  cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
  cell.detailTextLabel.font =
      [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
  cell.textLabel.adjustsFontForContentSizeCategory = YES;
  cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
  cell.textLabel.numberOfLines = 0;
  cell.detailTextLabel.numberOfLines = 0;
  cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
  cell.selectionStyle = action && enabled ? UITableViewCellSelectionStyleDefault
                                          : UITableViewCellSelectionStyleNone;
  if (action) {
    cell.textLabel.textColor =
        enabled ? UIColor.systemTealColor : UIColor.tertiaryLabelColor;
    cell.accessibilityTraits = UIAccessibilityTraitButton |
                               (enabled ? 0 : UIAccessibilityTraitNotEnabled);
  }
  return cell;
}
static void ipaSignIn(NSString *username) {
  UIAlertController *alert = [UIAlertController
      alertControllerWithTitle:@"Sign in"
                       message:@"Use the Apple Account you use to sideload "
                               @"your apps. Your password is never saved."
                preferredStyle:UIAlertControllerStyleAlert];
  [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
    field.placeholder = @"Apple Account";
    field.text = username;
    field.keyboardType = UIKeyboardTypeEmailAddress;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.textContentType = UITextContentTypeUsername;
    field.accessibilityLabel = @"Apple Account";
  }];
  [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
    field.placeholder = @"Password";
    field.secureTextEntry = YES;
    field.textContentType = UITextContentTypePassword;
    field.accessibilityLabel = @"Password";
  }];
  __weak UIAlertController *weakAlert = alert;
  [alert addAction:[UIAlertAction
                       actionWithTitle:@"Cancel"
                                 style:UIAlertActionStyleCancel
                               handler:^(UIAlertAction *action) {
                                 weakAlert.textFields.lastObject.text = @"";
                               }]];
  UIAlertAction *submit = [UIAlertAction
      actionWithTitle:@"Sign In"
                style:UIAlertActionStyleDefault
              handler:^(UIAlertAction *action) {
                UIAlertController *current = weakAlert;
                NSString *user = [current.textFields.firstObject.text
                    stringByTrimmingCharactersInSet:
                        NSCharacterSet.whitespaceAndNewlineCharacterSet];
                NSString *password = current.textFields.lastObject.text;
                current.textFields.lastObject.text = @"";
                ipaSend(@{
                  @"Kind" : @"login",
                  @"Username" : user ?: @"",
                  @"Password" : password ?: @""
                });
              }];
  [alert addAction:submit];
  submit.enabled = NO;
  for (UITextField *field in alert.textFields)
    [field addAction:[UIAction actionWithHandler:^(UIAction *action) {
             UIAlertController *current = weakAlert;
             if (current)
               submit.enabled =
                   [current.textFields.firstObject.text
                       stringByTrimmingCharactersInSet:
                           NSCharacterSet.whitespaceAndNewlineCharacterSet]
                           .length > 0 &&
                   current.textFields.lastObject.text.length > 0;
           }]
        forControlEvents:UIControlEventEditingChanged];
  [ipaTopController() presentViewController:alert animated:YES completion:nil];
}
@interface IPAStateTable : UITableViewController
@property(nonatomic) BOOL needsReload;
- (void)reloadWhenIdle;
@end
@implementation IPAStateTable
- (void)reloadWhenIdle {
  self.needsReload = YES;
  if (!self.isViewLoaded || self.tableView.dragging ||
      self.tableView.decelerating || self.tableView.tracking)
    return;
  self.needsReload = NO;
  [self.tableView reloadData];
}
- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];
  if (self.needsReload)
    [self reloadWhenIdle];
}
- (void)scrollViewDidEndDragging:(UIScrollView *)scrollView
                  willDecelerate:(BOOL)decelerate {
  if (!decelerate && self.needsReload)
    [self reloadWhenIdle];
}
- (void)scrollViewDidEndDecelerating:(UIScrollView *)scrollView {
  if (self.needsReload)
    [self reloadWhenIdle];
}
@end
static BOOL ipaStateChanged(NSDictionary *old, NSDictionary *state,
                            NSArray *keys) {
  for (NSString *key in keys)
    if (old[key] != state[key] && ![old[key] isEqual:state[key]])
      return YES;
  return NO;
}
@interface IPAAccount : IPAStateTable
- (void)showAccounts:(UIView *)source;
@end
@interface IPAAccounts : IPAStateTable
@end
static IPAAccounts *ipaAccountsView;
@interface IPACertificates : IPAStateTable
@end
static IPAAccount *ipaAccountView;
static IPACertificates *ipaCertificatesView;
@implementation IPAAccount
- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = @"Settings";
  self.navigationController.navigationBar.prefersLargeTitles = YES;
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 64;
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return 3;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  BOOL signedIn = [ipaShellState[@"Authenticated"] boolValue];
  if (section == 0)
    return signedIn ? 3 : 1;
  if (section == 1)
    return signedIn ? 3 : 2;
  return 0;
}
- (NSString *)tableView:(UITableView *)tableView
    titleForHeaderInSection:(NSInteger)section {
  return section == 0   ? @"Apple Account"
         : section == 1 ? @"Connection & Signing"
                        : nil;
}
- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  if (section == 0) {
    NSString *message = ipaShellState[@"AccountMessage"];
    if (message.length)
      return message;
    return [ipaShellState[@"Authenticated"] boolValue]
               ? ([ipaShellState[@"Teams"] count] > 1
                      ? @"New installs use the selected team. Refresh uses "
                        @"each app’s original team."
                      : @"Your apps use this developer team.")
               : @"Sign in to install and refresh apps. You can always view "
                 @"Apps without signing in. Use Accounts to manage saved "
                 @"sign-ins.";
  }
  if (section == 1) {
    NSString *message = ipaShellState[@"VPNMessage"];
    return message.length
               ? message
               : @"Local VPN connects IPA Loader to this iPhone. Enable it to "
                 @"install, refresh, and check apps. Your internet traffic "
                 @"stays on its usual connection.";
  }
  if (section == 2) {
    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    return [NSString
        stringWithFormat:@"Free accounts usually need to refresh every 7 days. "
                         @"If IPA Loader expires, reinstall it using your "
                         @"computer.\n\nIPA Loader %@ (%@)",
                         info[@"CFBundleShortVersionString"] ?: @"—",
                         info[@"CFBundleVersion"] ?: @"—"];
  }
  return nil;
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  BOOL signedIn = [ipaShellState[@"Authenticated"] boolValue],
       ready = ![ipaShellState[@"Busy"] boolValue] &&
               ![ipaShellState[@"VPNBusy"] boolValue];
  if (path.section == 0) {
    if (!signedIn)
      return ipaTextCell([ipaShellState[@"Accounts"] count] ? @"Accounts"
                                                            : @"Sign In",
                         nil, YES, ready);
    if (path.row == 0)
      return ipaTextCell(ipaShellState[@"Username"], ipaShellState[@"Quota"],
                         NO, YES);
    if (path.row == 1) {
      NSString *team = @"Choose team";
      for (NSDictionary *t in ipaShellState[@"Teams"])
        if ([t[@"ID"] isEqual:ipaShellState[@"TeamID"]])
          team = t[@"Name"];
      BOOL selectable = [ipaShellState[@"Teams"] count] > 1;
      UITableViewCell *cell =
          ipaTextCell(@"Developer Team", team, selectable, ready);
      cell.accessoryType = selectable
                               ? UITableViewCellAccessoryDisclosureIndicator
                               : UITableViewCellAccessoryNone;
      return cell;
    }
    return ipaTextCell(@"Switch Account", nil, YES, ready);
  }
  if (path.section == 1) {
    if (path.row == 0) {
      BOOL available = [ipaShellState[@"VPNAvailable"] boolValue];
      BOOL busy = [ipaShellState[@"VPNBusy"] boolValue];
      UITableViewCell *cell = ipaTextCell(
          @"Local VPN",
          busy
              ? ([ipaShellState[@"VPNRequested"] boolValue] ? @"Connecting…"
                                                            : @"Disconnecting…")
              : ([ipaShellState[@"VPNConnected"] boolValue]
                     ? @"Connected to this iPhone"
                     : (available ? @"Off · Required for app actions"
                                  : @"Not included in this build")),
          NO, YES);
      UISwitch *toggle = [UISwitch new];
      toggle.on = busy ? [ipaShellState[@"VPNRequested"] boolValue]
                       : [ipaShellState[@"VPNConnected"] boolValue];
      toggle.enabled = available && ready && !busy;
      toggle.accessibilityLabel = @"Local VPN";
      [toggle addTarget:self
                    action:@selector(toggleVPN:)
          forControlEvents:UIControlEventValueChanged];
      cell.accessoryView = toggle;
      return cell;
    }
    UITableViewCell *cell =
        ipaTextCell(path.row == 1 ? ([ipaShellState[@"VPNAvailable"] boolValue]
                                         ? @"Connection Help"
                                         : @"Connection Settings")
                                  : @"Certificates",
                    path.row == 1 ? ([ipaShellState[@"VPNAvailable"] boolValue]
                                         ? @"Using the local VPN"
                                         : @"Advanced connection options")
                                  : @"Manage development certificates",
                    YES, ready);
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
  }
  return [UITableViewCell new];
}
- (void)toggleVPN:(UISwitch *)toggle {
  toggle.enabled = NO;
  ipaSend(@{@"Kind" : @"vpn", @"Value" : toggle.on ? @"on" : @"off"});
}
- (void)tableView:(UITableView *)tableView
    didSelectRowAtIndexPath:(NSIndexPath *)path {
  [tableView deselectRowAtIndexPath:path animated:YES];
  if ([ipaShellState[@"Busy"] boolValue] ||
      [ipaShellState[@"VPNBusy"] boolValue])
    return;
  BOOL signedIn = [ipaShellState[@"Authenticated"] boolValue];
  if (path.section == 0) {
    if (!signedIn) {
      if ([ipaShellState[@"Accounts"] count])
        [self showAccounts:[tableView cellForRowAtIndexPath:path]];
      else
        ipaSignIn(ipaShellState[@"SignInUsername"] ?: @"");
      return;
    }
    if (path.row == 2) {
      [self showAccounts:[tableView cellForRowAtIndexPath:path]];
      return;
    }
    if (path.row == 1) {
      if ([ipaShellState[@"Teams"] count] <= 1)
        return;
      UIAlertController *choice = [UIAlertController
          alertControllerWithTitle:@"Developer Team"
                           message:nil
                    preferredStyle:UIAlertControllerStyleActionSheet];
      for (NSDictionary *team in ipaShellState[@"Teams"]) {
        [choice addAction:[UIAlertAction
                              actionWithTitle:
                                  [NSString
                                      stringWithFormat:
                                          @"%@%@",
                                          [team[@"ID"]
                                              isEqual:ipaShellState[@"TeamID"]]
                                              ? @"✓ "
                                              : @"",
                                          team[@"Name"]]
                                        style:UIAlertActionStyleDefault
                                      handler:^(UIAlertAction *action) {
                                        ipaSend(@{
                                          @"Kind" : @"team",
                                          @"Value" : team[@"ID"]
                                        });
                                      }]];
      }
      [choice addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                                 style:UIAlertActionStyleCancel
                                               handler:nil]];
      choice.popoverPresentationController.sourceView =
          [tableView cellForRowAtIndexPath:path];
      choice.popoverPresentationController.sourceRect =
          choice.popoverPresentationController.sourceView.bounds;
      [self presentViewController:choice animated:YES completion:nil];
    }
    return;
  }
  if (path.row == 0)
    return;
  if (path.row == 1) {
    ipaSend(@{@"Kind" : @"connection"});
    return;
  }
  ipaCertificatesView =
      [[IPACertificates alloc] initWithStyle:UITableViewStyleInsetGrouped];
  [self.navigationController pushViewController:ipaCertificatesView
                                       animated:YES];
  ipaSend(@{@"Kind" : @"certificates"});
}
- (void)showAccounts:(UIView *)source {
  UIAlertController *menu = [UIAlertController
      alertControllerWithTitle:@"Apple Accounts"
                       message:nil
                preferredStyle:UIAlertControllerStyleActionSheet];
  __weak UIAlertController *weakMenu = menu;
  BOOL signedIn = [ipaShellState[@"Authenticated"] boolValue];
  for (NSString *name in ipaShellState[@"Accounts"]) {
    BOOL active =
        signedIn && [name.lowercaseString
                        isEqual:[ipaShellState[@"Username"] lowercaseString]];
    [menu
        addAction:
            [UIAlertAction
                actionWithTitle:[NSString stringWithFormat:@"%@%@",
                                                           active ? @"✓ " : @"",
                                                           name]
                          style:UIAlertActionStyleDefault
                        handler:^(UIAlertAction *action) {
                          if (active)
                            return;
                          if ([name isEqual:ipaShellState[@"SignInUsername"]])
                            ipa_ios_dismiss(weakMenu, ^{
                              ipaSignIn(name);
                            });
                          else
                            ipaSend(@{@"Kind" : @"resume", @"Value" : name});
                        }]];
  }
  [menu addAction:[UIAlertAction
                      actionWithTitle:@"Add Another Account"
                                style:UIAlertActionStyleDefault
                              handler:^(UIAlertAction *action) {
                                ipa_ios_dismiss(weakMenu, ^{
                                  ipaSignIn(ipaShellState[@"SignInUsername"]
                                                ?: @"");
                                });
                              }]];
  if ([ipaShellState[@"Accounts"] count])
    [menu addAction:[UIAlertAction
                        actionWithTitle:@"Manage Accounts"
                                  style:UIAlertActionStyleDefault
                                handler:^(UIAlertAction *action) {
                                  ipa_ios_dismiss(weakMenu, ^{
                                    ipaAccountsView = [[IPAAccounts alloc]
                                        initWithStyle:
                                            UITableViewStyleInsetGrouped];
                                    [self.navigationController
                                        pushViewController:ipaAccountsView
                                                  animated:YES];
                                  });
                                }]];
  if (signedIn)
    [menu addAction:[UIAlertAction actionWithTitle:@"Sign Out"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
                                             ipaSend(@{@"Kind" : @"signout"});
                                           }]];
  [menu addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                           style:UIAlertActionStyleCancel
                                         handler:nil]];
  menu.popoverPresentationController.sourceView = source;
  menu.popoverPresentationController.sourceRect = source.bounds;
  [self presentViewController:menu animated:YES completion:nil];
}

@end
@implementation IPAAccounts
- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = @"Manage Accounts";
  self.navigationItem.rightBarButtonItem = self.editButtonItem;
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 64;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  return [ipaShellState[@"Accounts"] count];
}
- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  return [ipaShellState[@"Accounts"] count]
             ? @"Swipe an account to remove its saved sign-in from this "
               @"iPhone. Installed apps and their data stay on your device."
             : @"No saved accounts. Return to Settings to sign in.";
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  NSString *name = ipaShellState[@"Accounts"][path.row];
  BOOL active = [ipaShellState[@"Authenticated"] boolValue] &&
                [name.lowercaseString
                    isEqual:[ipaShellState[@"Username"] lowercaseString]];
  return ipaTextCell(name, active ? @"Current account" : @"Saved sign-in", NO,
                     YES);
}
- (BOOL)tableView:(UITableView *)tableView
    canEditRowAtIndexPath:(NSIndexPath *)path {
  return ![ipaShellState[@"Busy"] boolValue] &&
         ![ipaShellState[@"VPNBusy"] boolValue];
}
- (void)tableView:(UITableView *)tableView
    commitEditingStyle:(UITableViewCellEditingStyle)style
     forRowAtIndexPath:(NSIndexPath *)path {
  if (style != UITableViewCellEditingStyleDelete ||
      [ipaShellState[@"Busy"] boolValue])
    return;
  NSString *name = ipaShellState[@"Accounts"][path.row];
  UIAlertController *confirm = [UIAlertController
      alertControllerWithTitle:@"Remove Account?"
                       message:
                           [NSString
                               stringWithFormat:
                                   @"Forget the saved sign-in for %@ on this "
                                   @"iPhone? Your apps stay installed. You can "
                                   @"add the account again later.",
                                   name]
                preferredStyle:UIAlertControllerStyleAlert];
  [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
  [confirm
      addAction:[UIAlertAction
                    actionWithTitle:@"Remove"
                              style:UIAlertActionStyleDestructive
                            handler:^(UIAlertAction *action) {
                              ipaSend(@{@"Kind" : @"forget", @"Value" : name});
                            }]];
  [self presentViewController:confirm animated:YES completion:nil];
}
@end
static NSString *ipaCertificateDate(NSString *value) {
  NSISO8601DateFormatter *parser = [NSISO8601DateFormatter new];
  NSDate *date = [parser dateFromString:value];
  if (!date) {
    parser.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                           NSISO8601DateFormatWithFractionalSeconds;
    date = [parser dateFromString:value];
  }
  return date ? [NSDateFormatter
                    localizedStringFromDate:date
                                  dateStyle:NSDateFormatterMediumStyle
                                  timeStyle:NSDateFormatterNoStyle]
              : @"Unknown";
}
static NSString *ipaCertificateTeam(void) {
  for (NSDictionary *team in ipaShellState[@"Teams"])
    if ([team[@"ID"] isEqual:ipaShellState[@"TeamID"]])
      return [NSString stringWithFormat:@"%@ (%@)", team[@"Name"], team[@"ID"]];
  return ipaShellState[@"TeamID"] ?: @"Unknown team";
}
@implementation IPACertificates
- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = @"Certificates";
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 72;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  return [ipaShellState[@"Certificates"] count];
}
- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  NSString *message = ipaShellState[@"AccountMessage"];
  if (message.length)
    return message;
  return [ipaShellState[@"Busy"] boolValue]
             ? @"Loading…"
             : @"Revoking a certificate can stop every app signed with it from "
               @"opening. Only revoke one you no longer need.";
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  NSDictionary *cert = ipaShellState[@"Certificates"][path.row];
  NSString *detail = [NSString
      stringWithFormat:@"%@ · %@\nIssued %@ · Expires %@",
                       cert[@"Kind"] ?: @"Development", ipaCertificateTeam(),
                       ipaCertificateDate(cert[@"IssuedAt"]),
                       ipaCertificateDate(cert[@"ExpiresAt"])];
  return ipaTextCell(cert[@"Name"], detail, YES,
                     ![ipaShellState[@"Busy"] boolValue]);
}
- (void)tableView:(UITableView *)tableView
    didSelectRowAtIndexPath:(NSIndexPath *)path {
  [tableView deselectRowAtIndexPath:path animated:YES];
  if ([ipaShellState[@"Busy"] boolValue] ||
      [ipaShellState[@"VPNBusy"] boolValue])
    return;
  NSDictionary *cert = ipaShellState[@"Certificates"][path.row];
  NSString *message = [NSString
      stringWithFormat:
          @"%@\n%@\nSerial: %@\nIssued: %@\nExpires: %@\n\nApps signed with "
          @"this certificate "
          @"may stop opening. You will need to sign and install them again.",
          cert[@"Name"], ipaCertificateTeam(), cert[@"Serial"],
          ipaCertificateDate(cert[@"IssuedAt"]),
          ipaCertificateDate(cert[@"ExpiresAt"])];
  UIAlertController *alert =
      [UIAlertController alertControllerWithTitle:@"Revoke Certificate?"
                                          message:message
                                   preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                            style:UIAlertActionStyleCancel
                                          handler:nil]];
  [alert addAction:[UIAlertAction actionWithTitle:@"Revoke"
                                            style:UIAlertActionStyleDestructive
                                          handler:^(UIAlertAction *action) {
                                            ipaSend(@{
                                              @"Kind" : @"revoke",
                                              @"Value" : cert[@"SHA256"]
                                            });
                                          }]];
  [self presentViewController:alert animated:YES completion:nil];
}
@end
UIViewController *ipa_ios_account_controller(void) {
  ipaShellState = @{@"Accounts" : @[], @"Teams" : @[], @"Certificates" : @[]};
  for (NSString *name in @[
         NEVPNStatusDidChangeNotification, NEVPNConfigurationChangeNotification,
         UIApplicationDidBecomeActiveNotification
       ])
    [NSNotificationCenter.defaultCenter
        addObserverForName:name
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(NSNotification *note) {
                  ipaSend(@{
                    @"Kind" : [note.name
                        isEqual:NEVPNConfigurationChangeNotification]
                        ? @"vpnconfiguration"
                        : @"vpnstatus"
                  });
                }];
  ipaAccountView =
      [[IPAAccount alloc] initWithStyle:UITableViewStyleInsetGrouped];
  UINavigationController *nav = [[UINavigationController alloc]
      initWithRootViewController:ipaAccountView];
  nav.tabBarItem = [[UITabBarItem alloc]
      initWithTitle:@"Settings"
              image:[UIImage systemImageNamed:@"gearshape"]
                tag:1];
  return nav;
}
void ipa_ios_shell_update(const char *json) {
  NSString *text = @(json);
  dispatch_async(dispatch_get_main_queue(), ^{
    NSDictionary *state = [NSJSONSerialization
        JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding]
                   options:0
                     error:nil];
    if (![state isKindOfClass:NSDictionary.class])
      return;
    if ([ipaShellState isEqual:state])
      return;
    BOOL settingsChanged = ipaStateChanged(ipaShellState, state, @[
      @"Authenticated", @"Busy", @"Username", @"AccountMessage", @"Accounts",
      @"Teams", @"TeamID", @"Quota", @"SignInUsername", @"VPNAvailable",
      @"VPNConnected", @"VPNBusy", @"VPNRequested", @"VPNMessage"
    ]);
    BOOL certificatesChanged = ipaStateChanged(
        ipaShellState, state,
        @[ @"Certificates", @"Busy", @"AccountMessage", @"Teams", @"TeamID" ]);
    ipaShellState = state;
    if (settingsChanged) {
      [ipaAccountView reloadWhenIdle];
      [ipaAccountsView reloadWhenIdle];
    }
    if (certificatesChanged)
      [ipaCertificatesView reloadWhenIdle];
    ipa_ios_update_operation(state);
  });
}
void ipa_ios_cancel_action(void) { ipaSend(@{@"Kind" : @"cancel"}); }
void ipa_ios_refresh_all_action(void) { ipaSend(@{@"Kind" : @"refreshall"}); }
void ipa_ios_import_action(void) { ipaSend(@{@"Kind" : @"import"}); }
char *ipa_ios_prompt(const char *title, const char *message,
                     const char *initial, int secure, int code, int confirm) {
  if (NSThread.isMainThread)
    return NULL;
  __block char *result = NULL;
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  NSString *heading = @(title), *body = @(message), *value = @(initial);
  dispatch_async(dispatch_get_main_queue(), ^{
    UIViewController *root = ipaTopController();
    if (!root) {
      dispatch_semaphore_signal(done);
      return;
    }
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:heading
                         message:body
                  preferredStyle:UIAlertControllerStyleAlert];
    if (!confirm)
      [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = value;
        field.secureTextEntry = secure;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        if (code) {
          field.keyboardType = UIKeyboardTypeNumberPad;
          field.textContentType = UITextContentTypeOneTimeCode;
          field.placeholder = @"Six-digit code";
        }
      }];
    __weak UIAlertController *weakAlert = alert;
    [alert addAction:[UIAlertAction
                         actionWithTitle:@"Cancel"
                                   style:UIAlertActionStyleCancel
                                 handler:^(UIAlertAction *action) {
                                   weakAlert.textFields.firstObject.text = @"";
                                   ipa_ios_dismiss(weakAlert, ^{
                                     dispatch_semaphore_signal(done);
                                   });
                                 }]];
    UIAlertAction *submit = [UIAlertAction
        actionWithTitle:confirm ? @"Choose IPA" : @"Continue"
                  style:UIAlertActionStyleDefault
                handler:^(UIAlertAction *action) {
                  UIAlertController *current = weakAlert;
                  NSString *answer =
                      confirm ? @"yes" : current.textFields.firstObject.text;
                  result = strdup(answer.UTF8String ?: "");
                  current.textFields.firstObject.text = @"";
                  ipa_ios_dismiss(current, ^{
                    dispatch_semaphore_signal(done);
                  });
                }];
    [alert addAction:submit];
    if (code) {
      submit.enabled = NO;
      [alert.textFields.firstObject
                 addAction:[UIAction actionWithHandler:^(UIAction *action) {
                   NSString *text = weakAlert.textFields.firstObject.text;
                   submit.enabled =
                       text.length == 6 &&
                       [text rangeOfCharacterFromSet:
                                 [[NSCharacterSet
                                     characterSetWithCharactersInString:
                                         @"0123456789"] invertedSet]]
                               .location == NSNotFound;
                 }]
          forControlEvents:UIControlEventEditingChanged];
    }
    [root presentViewController:alert animated:YES completion:nil];
  });
  dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
  return result;
}
@interface IPAImport
    : UITableViewController <UIAdaptivePresentationControllerDelegate>
@property(nonatomic, copy) NSDictionary *info;
@property(nonatomic) dispatch_semaphore_t done;
@property(nonatomic) BOOL accepted, finished, keepIPA;
@end
@implementation IPAImport
- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = @"Install App";
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 64;
  self.navigationItem.leftBarButtonItem =
      ipa_ios_bar_button(@"Cancel", self, @selector(cancel), NO);
  self.navigationItem.rightBarButtonItem =
      ipa_ios_bar_button(@"Install", self, @selector(install), YES);
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return 2;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  return section == 0 ? 3 : 1;
}
- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  if (section == 0)
    return [NSString
        stringWithFormat:@"Install on this iPhone using %@.",
                         ipaShellState[@"Username"] ?: @"your Apple Account"];
  return @"Saves an extra copy for full signing. When off, profile refresh "
         @"still works; full signing may ask you to choose the original IPA "
         @"again.";
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  if (path.section == 1) {
    NSString *size = [NSByteCountFormatter
        stringFromByteCount:[self.info[@"Size"] longLongValue]
                 countStyle:NSByteCountFormatterCountStyleFile];
    UITableViewCell *cell = ipaTextCell(
        @"Keep IPA for Refresh",
        [NSString stringWithFormat:@"Uses %@ of additional storage", size], NO,
        YES);
    UISwitch *toggle = [UISwitch new];
    toggle.on = self.keepIPA;
    toggle.accessibilityLabel = @"Keep IPA for Refresh";
    [toggle addTarget:self
                  action:@selector(changeKeepIPA:)
        forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
    return cell;
  }
  if (path.row == 0) {
    UITableViewCell *cell =
        [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                               reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    NSString *icon = self.info[@"Icon"];
    UIImage *image =
        [icon isKindOfClass:NSString.class]
            ? [UIImage
                  imageWithData:[[NSData alloc] initWithBase64EncodedString:icon
                                                                    options:0]]
            : nil;
    UIImageView *iconView =
        ipa_ios_app_icon(image ?: [UIImage systemImageNamed:@"app.fill"], 56);
    UILabel *name = [UILabel new];
    name.text = self.info[@"Name"];
    name.numberOfLines = 0;
    name.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    name.adjustsFontForContentSizeCategory = YES;
    UIStackView *identity =
        [[UIStackView alloc] initWithArrangedSubviews:@[ iconView, name ]];
    identity.axis = UILayoutConstraintAxisHorizontal;
    identity.alignment = UIStackViewAlignmentCenter;
    identity.spacing = 14;
    identity.translatesAutoresizingMaskIntoConstraints = NO;
    [cell.contentView addSubview:identity];
    cell.contentView.directionalLayoutMargins =
        NSDirectionalEdgeInsetsMake(16, 16, 16, 16);
    [NSLayoutConstraint activateConstraints:@[
      [identity.topAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .topAnchor],
      [identity.bottomAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .bottomAnchor],
      [identity.leadingAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .leadingAnchor],
      [identity.trailingAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .trailingAnchor]
    ]];
    return cell;
  }
  return ipaTextCell(path.row == 1 ? @"Version" : @"Bundle Identifier",
                     path.row == 1
                         ? [NSString stringWithFormat:@"%@ (%@)",
                                                      self.info[@"Version"],
                                                      self.info[@"Build"]]
                         : self.info[@"BundleID"],
                     NO, YES);
}
- (void)changeKeepIPA:(UISwitch *)toggle {
  self.keepIPA = toggle.on;
}
- (void)finish:(BOOL)accepted {
  if (self.finished)
    return;
  self.finished = YES;
  self.accepted = accepted;
  dispatch_semaphore_signal(self.done);
}
- (void)cancel {
  [self dismissViewControllerAnimated:YES
                           completion:^{
                             [self finish:NO];
                           }];
}
- (void)install {
  [self dismissViewControllerAnimated:YES
                           completion:^{
                             [self finish:YES];
                           }];
}
- (void)presentationControllerDidDismiss:
    (UIPresentationController *)controller {
  [self finish:NO];
}
@end
int ipa_ios_confirm_import(const char *json) {
  if (NSThread.isMainThread)
    return 0;
  NSString *text = @(json);
  IPAImport *view =
      [[IPAImport alloc] initWithStyle:UITableViewStyleInsetGrouped];
  view.done = dispatch_semaphore_create(0);
  view.info = [NSJSONSerialization
      JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding]
                 options:0
                   error:nil];
  dispatch_async(dispatch_get_main_queue(), ^{
    UIViewController *root = ipaTopController();
    if (!root) {
      [view finish:NO];
      return;
    }
    UINavigationController *nav =
        [[UINavigationController alloc] initWithRootViewController:view];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    nav.presentationController.delegate = view;
    [root presentViewController:nav animated:YES completion:nil];
  });
  dispatch_semaphore_wait(view.done, DISPATCH_TIME_FOREVER);
  return view.accepted ? (view.keepIPA ? 2 : 1) : 0;
}
@interface IPALoaderApplication : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation IPALoaderApplication
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)options {
  self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
  self.window.tintColor = UIColor.systemTealColor;
  self.window.rootViewController = ipa_ios_make_root();
  [self.window makeKeyAndVisible];
  dispatch_async(dispatch_get_main_queue(), ^{
    ipa_go_shell_started();
  });
  return YES;
}
@end
void ipa_ios_run(void) {
  @autoreleasepool {
    char *argv[] = {"ipa-loader", NULL};
    UIApplicationMain(1, argv, nil,
                      NSStringFromClass(IPALoaderApplication.class));
  }
}
