//go:build ios
#import "controls_ios.h"
#import "shell_ios.h"
#import <UIKit/UIKit.h>

extern void ipa_go_apps_load(int check);
extern void ipa_go_apps_action(char *bundle);

@interface IPALoaderTabs : UITabBarController
@end
@implementation IPALoaderTabs
@end

@interface IPALoaderApps : UITableViewController
@property(nonatomic, copy) NSArray<NSDictionary *> *apps;
@property(nonatomic, copy) NSString *message;
@property(nonatomic, strong) NSTimer *timer;
@property(nonatomic) BOOL checked;
@property(nonatomic, copy) NSDictionary *operation;
@property(nonatomic, copy) NSDictionary *pendingPayload;
@property(nonatomic) BOOL needsReload;
- (void)reloadWhenIdle;
- (void)updateOperationSheet;
- (void)updateControls;
- (void)refreshApp:(NSDictionary *)app;
- (void)showDetails:(NSDictionary *)app;
@end
@interface IPAAppIdentity : UIStackView
@property(nonatomic, copy) void (^openDetails)(void);
@end
@implementation IPAAppIdentity
- (BOOL)accessibilityActivate {
  if (self.openDetails) {
    self.openDetails();
    return YES;
  }
  return NO;
}
@end
@interface IPALoaderAppDetails : UITableViewController
@property(nonatomic, copy) NSDictionary *app;
@end
static IPALoaderApps *ipaApps;
static UITabBarController *ipaTabs;
static UIViewController *ipaAccountNavigation;
static BOOL ipaSignedIn;
static BOOL ipaWorking;
static BOOL ipaVPNRequired;
static BOOL ipaVPNConnected;
static BOOL ipaVPNBusy;
static NSInteger ipaEligibleRefreshes;

static NSDate *ipaAppDate(id value) {
  if (![value isKindOfClass:NSString.class] || [value hasPrefix:@"0001"])
    return nil;
  NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
  NSDate *date = [formatter dateFromString:value];
  if (!date) {
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                              NSISO8601DateFormatWithFractionalSeconds;
    date = [formatter dateFromString:value];
  }
  return date;
}
static NSString *ipaRemaining(NSDictionary *app) {
  NSDate *expiry = ipaAppDate(app[@"Expires"]);
  if (!expiry)
    return @"Expiry unavailable";
  NSTimeInterval seconds = expiry.timeIntervalSinceNow;
  if (seconds <= 0)
    return @"Expired";
  if (seconds < 3600)
    return @"Less than 1 hour left";
  if (seconds < 86400) {
    NSInteger hours = (NSInteger)ceil(seconds / 3600);
    return [NSString stringWithFormat:@"%ld %@ left", (long)hours,
                                      hours == 1 ? @"hour" : @"hours"];
  }
  NSInteger days = (NSInteger)ceil(seconds / 86400);
  return [NSString stringWithFormat:@"%ld %@ left", (long)days,
                                    days == 1 ? @"day" : @"days"];
}
static UIColor *ipaExpiryColor(NSDictionary *app) {
  NSDate *date = ipaAppDate(app[@"Expires"]);
  if (!date)
    return UIColor.secondaryLabelColor;
  if (date.timeIntervalSinceNow <= 0)
    return UIColor.systemRedColor;
  if (date.timeIntervalSinceNow < 86400)
    return UIColor.systemOrangeColor;
  return UIColor.systemTealColor;
}
static NSString *ipaAccount(NSDictionary *app) {
  NSString *account = app[@"Account"];
  return account.length ? account : @"Account unknown";
}
static NSString *ipaLastRefreshed(NSDictionary *app) {
  NSDate *date = ipaAppDate(app[@"Refreshed"]);
  if (!date)
    return @"Refresh history unavailable";
  NSRelativeDateTimeFormatter *formatter = [NSRelativeDateTimeFormatter new];
  formatter.dateTimeStyle = NSRelativeDateTimeFormatterStyleNamed;
  return [NSString
      stringWithFormat:@"Refreshed %@",
                       [formatter localizedStringForDate:date
                                          relativeToDate:NSDate.date]];
}
static NSString *ipaExactDate(id value) {
  NSDate *date = ipaAppDate(value);
  return date ? [NSDateFormatter
                    localizedStringFromDate:date
                                  dateStyle:NSDateFormatterMediumStyle
                                  timeStyle:NSDateFormatterShortStyle]
              : @"Unknown";
}
static UILabel *ipaAppLabel(NSString *text, UIFontTextStyle style,
                            UIColor *color) {
  UILabel *label = [UILabel new];
  label.text = text;
  label.font = [UIFont preferredFontForTextStyle:style];
  label.textColor = color;
  label.adjustsFontForContentSizeCategory = YES;
  label.numberOfLines = 0;
  return label;
}
static UIButton *ipaRefreshButton(NSDictionary *app) {
  UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
  UIButtonConfiguration *config =
      UIButtonConfiguration.tintedButtonConfiguration;
  BOOL refreshing = ipaWorking &&
                    ([ipaApps.operation[@"Operation"] isEqual:@"refresh"] ||
                     [ipaApps.operation[@"Operation"] isEqual:@"refreshall"]) &&
                    [ipaApps.operation[@"Target"] isEqual:app[@"BundleID"]];
  config.title = refreshing ? nil : @"Refresh";
  config.showsActivityIndicator = refreshing;
  config.cornerStyle = UIButtonConfigurationCornerStyleCapsule;
  config.contentInsets = NSDirectionalEdgeInsetsMake(10, 14, 10, 14);
  button.configuration = config;
  button.tintColor = UIColor.systemTealColor;
  button.enabled = ipaSignedIn && !ipaWorking && !ipaVPNBusy &&
                   (!ipaVPNRequired || ipaVPNConnected);
  button.accessibilityLabel = [NSString
      stringWithFormat:@"%@ %@", refreshing ? @"Refreshing" : @"Refresh",
                       app[@"Name"]];
  button.accessibilityHint = ipaSignedIn ? @"Renew the app’s signing profile."
                                         : @"Sign in to refresh this app.";
  [button.heightAnchor constraintGreaterThanOrEqualToConstant:44].active = YES;
  [button addAction:[UIAction actionWithHandler:^(UIAction *action) {
            [ipaApps refreshApp:app];
          }]
      forControlEvents:UIControlEventTouchUpInside];
  return button;
}

@implementation IPALoaderAppDetails
- (void)scrollViewDidEndDragging:(UIScrollView *)scrollView
                  willDecelerate:(BOOL)decelerate {
  if (!decelerate && ipaApps.needsReload)
    [ipaApps reloadWhenIdle];
}
- (void)scrollViewDidEndDecelerating:(UIScrollView *)scrollView {
  if (ipaApps.needsReload)
    [ipaApps reloadWhenIdle];
}

- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = self.app[@"Name"];
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 64;
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return 2;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  return section == 0 ? 6 : 1;
}
- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  if (section == 0)
    return
        [self.app[@"Account"] length]
            ? @"The account used to install, refresh, or verify signing for "
              @"this app."
            : @"The account wasn’t recorded for this installation. It will "
              @"appear after a successful install or refresh with IPA Loader.";
  if (!ipaSignedIn)
    return @"Sign in to refresh this app.";
  if ([ipaApps.operation[@"Target"] isEqual:self.app[@"BundleID"]] &&
      [ipaApps.operation[@"Message"] length])
    return ipaApps.operation[@"Message"];
  if ([self.app[@"Self"] boolValue])
    return @"Profile renewal doesn’t reinstall IPA Loader. If full signing is "
           @"needed, return to the Home Screen when installation starts, then "
           @"reopen it.";
  return @"IPA Loader renews signing profiles when possible. If full signing "
         @"is needed, it uses the saved IPA or asks you to choose the original "
         @"file.";
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  UITableViewCell *cell =
      [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                             reuseIdentifier:nil];
  cell.selectionStyle = UITableViewCellSelectionStyleNone;
  if (path.section == 1) {
    UIButton *button = ipaRefreshButton(self.app);
    UIStackView *actions =
        [[UIStackView alloc] initWithArrangedSubviews:@[ button ]];
    actions.axis = UILayoutConstraintAxisVertical;
    actions.spacing = 12;
    actions.translatesAutoresizingMaskIntoConstraints = NO;
    [cell.contentView addSubview:actions];
    [NSLayoutConstraint activateConstraints:@[
      [actions.topAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .topAnchor],
      [actions.bottomAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .bottomAnchor],
      [actions.leadingAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .leadingAnchor],
      [actions.trailingAnchor
          constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                      .trailingAnchor]
    ]];
    return cell;
  }
  NSArray *titles = @[
    @"Apple Account", @"Expires", @"Last refreshed", @"Version",
    @"Developer team", @"Bundle identifier"
  ];
  NSString *version = self.app[@"Version"];
  NSString *build = self.app[@"Build"];
  NSString *versionText = version.length ? version : @"Unknown";
  if (build.length)
    versionText = [versionText stringByAppendingFormat:@" (%@)", build];
  NSString *team = self.app[@"Team"];
  NSArray *values = @[
    ipaAccount(self.app), ipaExactDate(self.app[@"Expires"]),
    ipaExactDate(self.app[@"Refreshed"]), versionText,
    team.length ? team : @"Unknown", self.app[@"BundleID"] ?: @""
  ];
  cell.textLabel.text = titles[path.row];
  cell.textLabel.font =
      [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
  cell.textLabel.adjustsFontForContentSizeCategory = YES;
  cell.textLabel.numberOfLines = 0;
  cell.detailTextLabel.text = values[path.row];
  cell.detailTextLabel.font =
      [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
  cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
  cell.detailTextLabel.numberOfLines = 0;
  cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
  return cell;
}
@end

@interface IPAProgress
    : UIViewController <UIAdaptivePresentationControllerDelegate>
@property(nonatomic, strong) NSNumber *identifier;
@property(nonatomic, strong) UILabel *heading;
@property(nonatomic, strong) UILabel *message;
@property(nonatomic, strong) UIProgressView *progress;
@property(nonatomic, strong) UIButton *details;
@property(nonatomic, strong) UITextView *logs;
- (void)apply:(NSDictionary *)state;
@end
static IPAProgress *ipaProgress;
static NSNumber *ipaDismissedOperation;
@implementation IPAProgress
- (void)viewDidLoad {
  [super viewDidLoad];
  self.view.backgroundColor = UIColor.systemBackgroundColor;
  self.heading = ipaAppLabel(@"", UIFontTextStyleTitle2, UIColor.labelColor);
  self.message =
      ipaAppLabel(@"", UIFontTextStyleBody, UIColor.secondaryLabelColor);
  self.progress = [UIProgressView new];
  self.details = [UIButton buttonWithType:UIButtonTypeSystem];
  UIButtonConfiguration *disclosure =
      UIButtonConfiguration.tintedButtonConfiguration;
  disclosure.title = @"Show Details";
  disclosure.image = [UIImage systemImageNamed:@"chevron.down"];
  disclosure.imagePlacement = NSDirectionalRectEdgeTrailing;
  disclosure.imagePadding = 8;
  disclosure.contentInsets = NSDirectionalEdgeInsetsMake(12, 16, 12, 16);
  disclosure.cornerStyle = UIButtonConfigurationCornerStyleMedium;
  self.details.configuration = disclosure;
  self.details.tintColor = UIColor.systemTealColor;
  self.details.accessibilityHint = @"Expand the full activity log.";
  [self.details.heightAnchor constraintGreaterThanOrEqualToConstant:44].active =
      YES;
  [self.details addTarget:self
                   action:@selector(toggleDetails)
         forControlEvents:UIControlEventTouchUpInside];
  self.logs = [UITextView new];
  self.logs.editable = NO;
  self.logs.hidden = YES;
  self.logs.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
  self.logs.scrollEnabled = NO;
  self.logs.textContainerInset = UIEdgeInsetsMake(12, 12, 12, 12);
  self.logs.textContainer.lineFragmentPadding = 0;
  self.logs.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
  self.logs.textColor = UIColor.labelColor;
  self.logs.layer.cornerRadius = 12;
  self.logs.layer.cornerCurve = kCACornerCurveContinuous;
  self.logs.adjustsFontForContentSizeCategory = YES;
  UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
    self.heading, self.message, self.progress, self.details, self.logs
  ]];
  stack.axis = UILayoutConstraintAxisVertical;
  stack.spacing = 16;
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  UIScrollView *scroll = [UIScrollView new];
  scroll.translatesAutoresizingMaskIntoConstraints = NO;
  [self.view addSubview:scroll];
  [scroll addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [scroll.topAnchor
        constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
    [scroll.bottomAnchor
        constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor],
    [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
    [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor
                                    constant:24],
    [stack.bottomAnchor
        constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor
                       constant:-24],
    [stack.leadingAnchor
        constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor
                       constant:24],
    [stack.trailingAnchor
        constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor
                       constant:-24],
    [stack.widthAnchor
        constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor
                       constant:-48]
  ]];
}
- (void)toggleDetails {
  self.logs.hidden = !self.logs.hidden;
  UIButtonConfiguration *disclosure = self.details.configuration;
  disclosure.title = self.logs.hidden ? @"Show Details" : @"Hide Details";
  disclosure.image = [UIImage
      systemImageNamed:self.logs.hidden ? @"chevron.down" : @"chevron.up"];
  self.details.configuration = disclosure;
  self.details.accessibilityValue =
      self.logs.hidden ? @"Collapsed" : @"Expanded";
  if (!self.logs.hidden)
    self.navigationController.sheetPresentationController
        .selectedDetentIdentifier =
        UISheetPresentationControllerDetentIdentifierLarge;
}
- (void)finish {
  ipaDismissedOperation = self.identifier;
  [self dismissViewControllerAnimated:YES completion:nil];
}
- (void)cancel {
  ipa_ios_cancel_action();
  self.navigationItem.rightBarButtonItem.enabled = NO;
}
- (void)presentationControllerDidDismiss:
    (UIPresentationController *)presentationController {
  ipaDismissedOperation = self.identifier;
}
- (void)apply:(NSDictionary *)state {
  [self loadViewIfNeeded];
  BOOL busy = [state[@"Busy"] boolValue], failed = [state[@"Failed"] boolValue];
  NSString *kind = state[@"Operation"];
  self.title =
      [kind isEqual:@"install"]
          ? @"Install App"
          : ([kind isEqual:@"refreshall"] ? @"Refresh All" : @"Refresh App");
  NSString *name = @"App";
  for (NSDictionary *app in ipaApps.apps)
    if ([app[@"BundleID"] isEqual:state[@"Target"]])
      name = app[@"Name"];
  self.heading.text =
      busy ? ([kind isEqual:@"refreshall"]
                  ? @"Refreshing your apps"
                  : ([kind isEqual:@"install"]
                         ? @"Installing app"
                         : [@"Refreshing " stringByAppendingString:name]))
           : (failed ? @"Needs attention" : @"Done");
  self.message.text = state[@"Message"];
  self.message.textColor =
      failed ? UIColor.systemRedColor : UIColor.secondaryLabelColor;
  self.progress.hidden = !busy;
  self.progress.progress = MAX(0, MIN(1, [state[@"Fraction"] floatValue]));
  NSArray *results = state[@"Results"];
  NSString *logs = [state[@"Logs"] componentsJoinedByString:@"\n"];
  NSString *activity =
      results.count
          ? [NSString stringWithFormat:@"%@\n\nActivity\n%@",
                                       [results componentsJoinedByString:@"\n"],
                                       logs]
          : logs;
  NSMutableParagraphStyle *paragraph = [NSMutableParagraphStyle new];
  paragraph.lineSpacing = 1;
  paragraph.paragraphSpacing = 3;
  self.logs.attributedText = [[NSAttributedString alloc]
      initWithString:activity ?: @""
          attributes:@{
            NSFontAttributeName :
                [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote],
            NSForegroundColorAttributeName : UIColor.labelColor,
            NSParagraphStyleAttributeName : paragraph
          }];
  [self.logs invalidateIntrinsicContentSize];
  self.navigationItem.rightBarButtonItem =
      ipa_ios_bar_button(busy ? @"Cancel" : @"Done", self,
                         busy ? @selector(cancel) : @selector(finish), NO);
  self.navigationController.modalInPresentation = busy;
}
@end

@implementation IPALoaderApps
- (void)reloadWhenIdle {
  self.needsReload = YES;
  if (!self.isViewLoaded)
    return;
  UITableViewController *details =
      [self.navigationController.topViewController
          isKindOfClass:IPALoaderAppDetails.class]
          ? (UITableViewController *)self.navigationController.topViewController
          : nil;
  if (self.tableView.dragging || self.tableView.decelerating ||
      self.tableView.tracking || details.tableView.dragging ||
      details.tableView.decelerating || details.tableView.tracking)
    return;
  if (self.pendingPayload) {
    self.apps = self.pendingPayload[@"Apps"];
    self.message = self.pendingPayload[@"Message"];
    self.pendingPayload = nil;
  }
  self.needsReload = NO;
  [self.tableView reloadData];
  if (details) {
    IPALoaderAppDetails *view = (IPALoaderAppDetails *)details;
    for (NSDictionary *app in self.apps)
      if ([app[@"BundleID"] isEqual:view.app[@"BundleID"]]) {
        view.app = app;
        break;
      }
    [details.tableView reloadData];
  }
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

- (void)viewDidLoad {
  [super viewDidLoad];
  self.title = @"Apps";
  self.navigationController.navigationBar.prefersLargeTitles = YES;
  self.tableView.rowHeight = UITableViewAutomaticDimension;
  self.tableView.estimatedRowHeight = 120;
  self.refreshControl = [UIRefreshControl new];
  [self.refreshControl addTarget:self
                          action:@selector(checkApps)
                forControlEvents:UIControlEventValueChanged];
  [self updateControls];
  [[NSNotificationCenter defaultCenter]
      addObserver:self
         selector:@selector(foreground)
             name:UIApplicationDidBecomeActiveNotification
           object:nil];
  [[NSNotificationCenter defaultCenter]
      addObserver:self
         selector:@selector(updateTimes)
             name:UIContentSizeCategoryDidChangeNotification
           object:nil];
}
- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];
  ipa_go_apps_load(0);
  if (self.needsReload)
    [self reloadWhenIdle];
  [self.timer invalidate];
  self.timer = [NSTimer scheduledTimerWithTimeInterval:60
                                                target:self
                                              selector:@selector(updateTimes)
                                              userInfo:nil
                                               repeats:YES];
}
- (void)viewDidAppear:(BOOL)animated {
  [super viewDidAppear:animated];
  if (!self.checked)
    [self checkApps];
  [self updateOperationSheet];
}
- (void)viewDidDisappear:(BOOL)animated {
  [super viewDidDisappear:animated];
  [self.timer invalidate];
  self.timer = nil;
}
- (void)updateTimes {
  [self reloadWhenIdle];
}
- (void)foreground {
  if (self.view.window)
    ipa_go_apps_load(0);
}
- (void)checkApps {
  if (!ipaWorking && !ipaVPNBusy && (!ipaVPNRequired || ipaVPNConnected)) {
    self.checked = YES;
    ipa_go_apps_load(1);
  } else
    [self.refreshControl endRefreshing];
}
- (void)signIn {
  ipa_ios_show_account();
}
- (void)refreshAll {
  if (!ipaSignedIn || ipaWorking || ipaVPNBusy ||
      (ipaVPNRequired && !ipaVPNConnected) || ipaEligibleRefreshes == 0)
    return;
  ipaWorking = YES;
  [self updateControls];
  ipa_ios_refresh_all_action();
}
- (void)importApp {
  if (!ipaSignedIn || ipaWorking || ipaVPNBusy ||
      (ipaVPNRequired && !ipaVPNConnected))
    return;
  ipaWorking = YES;
  [self updateControls];
  ipa_ios_import_action();
}
- (void)updateOperationSheet {
  self.tableView.tableHeaderView = nil;
  NSDictionary *state = self.operation;
  if ([state[@"Cancelled"] boolValue]) {
    if ([ipaProgress.identifier isEqual:state[@"OperationID"]])
      [ipaProgress finish];
    return;
  }
  NSString *kind = state[@"Operation"], *message = state[@"Message"];
  if (!message.length || [kind isEqual:@"account"] ||
      [kind isEqual:@"signin"] || [message isEqual:@"Preparing…"])
    return;
  NSNumber *identifier = state[@"OperationID"] ?: @0;
  if ([ipaDismissedOperation isEqual:identifier])
    return;
  if (!ipaProgress || ![ipaProgress.identifier isEqual:identifier]) {
    if (self.navigationController.presentedViewController)
      return;
    ipaProgress = [IPAProgress new];
    ipaProgress.identifier = identifier;
    UINavigationController *nav =
        [[UINavigationController alloc] initWithRootViewController:ipaProgress];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    nav.view.tintColor = UIColor.systemTealColor;
    nav.sheetPresentationController.detents = @[
      UISheetPresentationControllerDetent.mediumDetent,
      UISheetPresentationControllerDetent.largeDetent
    ];
    nav.sheetPresentationController.prefersGrabberVisible = YES;
    nav.presentationController.delegate = ipaProgress;
    [self.navigationController presentViewController:nav
                                            animated:YES
                                          completion:nil];
  }
  [ipaProgress apply:state];
}
- (void)help {
  UIAlertController *alert = [UIAlertController
      alertControllerWithTitle:@"Keeping apps refreshed"
                       message:
                           @"Refresh your apps before their signing profiles "
                           @"expire. Free accounts usually need to refresh "
                           @"every 7 days, including IPA Loader.\n\nUse Wi-Fi "
                           @"and keep your connection ready. If IPA Loader "
                           @"expires, reinstall it using your "
                           @"computer.\n\nPull down to check installed apps. "
                           @"Tap an app for exact dates and account details."
                preferredStyle:UIAlertControllerStyleAlert];
  [alert addAction:[UIAlertAction actionWithTitle:@"Done"
                                            style:UIAlertActionStyleCancel
                                          handler:nil]];
  [self presentViewController:alert animated:YES completion:nil];
}
- (void)updateControls {
  if (!self.navigationItem.rightBarButtonItem)
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@""
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(signIn)];
  self.navigationItem.rightBarButtonItem.title =
      ipaSignedIn ? @"Refresh All" : @"Sign In";
  self.navigationItem.rightBarButtonItem.action =
      ipaSignedIn ? @selector(refreshAll) : @selector(signIn);
  self.navigationItem.rightBarButtonItem.enabled =
      ipaSignedIn
          ? (!ipaWorking && !ipaVPNBusy &&
             (!ipaVPNRequired || ipaVPNConnected) && ipaEligibleRefreshes > 0)
          : !ipaWorking;
  if (!self.navigationItem.leftBarButtonItem)
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
                             target:self
                             action:@selector(importApp)];
  self.navigationItem.leftBarButtonItem.accessibilityLabel = @"Install an IPA";
  self.navigationItem.leftBarButtonItem.enabled =
      ipaSignedIn && !ipaWorking && !ipaVPNBusy &&
      (!ipaVPNRequired || ipaVPNConnected);
  self.refreshControl.enabled =
      !ipaWorking && !ipaVPNBusy && (!ipaVPNRequired || ipaVPNConnected);
  [self reloadWhenIdle];
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return 1;
}
- (NSInteger)tableView:(UITableView *)tableView
    numberOfRowsInSection:(NSInteger)section {
  return self.apps.count;
}
- (NSString *)tableView:(UITableView *)tableView
    titleForHeaderInSection:(NSInteger)section {
  return @"On this iPhone";
}
- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  NSString *message = self.message.length
                          ? self.message
                          : @"Pull down to check for installed apps.";
  if (ipaVPNRequired && !ipaVPNConnected)
    return @"Enable Local VPN in Settings to install, refresh, and check apps. "
           @"Saved app details remain available.";
  if (!ipaSignedIn)
    return [@"Sign in to install or refresh apps.\n"
        stringByAppendingString:message];
  if (ipaSignedIn && ipaEligibleRefreshes == 0 && self.apps.count > 0)
    return [message
        stringByAppendingString:@"\nRefresh an app individually to verify its "
                                @"account before using Refresh All."];
  return message;
}
- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)path {
  UITableViewCell *cell =
      [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                             reuseIdentifier:nil];
  NSDictionary *app = self.apps[path.row];
  BOOL large = UIContentSizeCategoryIsAccessibilityCategory(
      self.traitCollection.preferredContentSizeCategory);
  UILabel *name =
      ipaAppLabel(app[@"Name"], UIFontTextStyleHeadline, UIColor.labelColor);
  UILabel *account = ipaAppLabel(ipaAccount(app), UIFontTextStyleCaption1,
                                 UIColor.secondaryLabelColor);
  if (!large) {
    account.numberOfLines = 1;
    account.lineBreakMode = NSLineBreakByTruncatingMiddle;
  }
  UILabel *remaining = ipaAppLabel(
      ipaRemaining(app), UIFontTextStyleSubheadline, ipaExpiryColor(app));
  UILabel *refreshed =
      ipaAppLabel(ipaLastRefreshed(app), UIFontTextStyleCaption1,
                  UIColor.secondaryLabelColor);
  IPAAppIdentity *labels = [[IPAAppIdentity alloc]
      initWithArrangedSubviews:@[ name, account, remaining, refreshed ]];
  labels.axis = UILayoutConstraintAxisVertical;
  labels.spacing = 3;
  labels.isAccessibilityElement = YES;
  labels.accessibilityTraits = UIAccessibilityTraitButton;
  labels.openDetails = ^{
    [ipaApps showDetails:app];
  };
  labels.accessibilityLabel = [NSString
      stringWithFormat:@"%@, %@, %@, %@", app[@"Name"], ipaAccount(app),
                       ipaRemaining(app), ipaLastRefreshed(app)];
  labels.accessibilityHint = @"Double-tap for app details.";
  UIImage *image = nil;
  NSString *icon = app[@"Icon"];
  if ([icon isKindOfClass:NSString.class] && icon.length)
    image =
        [UIImage imageWithData:[[NSData alloc] initWithBase64EncodedString:icon
                                                                   options:0]];
  if (!image && [app[@"Self"] boolValue])
    image = [UIImage imageNamed:@"AppIcon180"];
  BOOL placeholder = !image && ![app[@"Self"] boolValue];
  if (!image && !placeholder)
    image = [UIImage systemImageNamed:@"arrow.down.app.fill"];
  UIImageView *iconView = ipa_ios_app_icon(image, 44);
  if (placeholder) {
    iconView.backgroundColor =
        [UIColor.systemTealColor colorWithAlphaComponent:0.12];
    UILabel *initial = ipaAppLabel(
        [app[@"Name"] length]
            ? [[app[@"Name"]
                  substringWithRange:
                      [app[@"Name"] rangeOfComposedCharacterSequenceAtIndex:0]]
                  uppercaseString]
            : @"?",
        UIFontTextStyleHeadline, UIColor.systemTealColor);
    initial.font = [UIFont systemFontOfSize:22 weight:UIFontWeightSemibold];
    initial.adjustsFontForContentSizeCategory = NO;
    initial.textAlignment = NSTextAlignmentCenter;
    initial.translatesAutoresizingMaskIntoConstraints = NO;
    [iconView addSubview:initial];
    [NSLayoutConstraint activateConstraints:@[
      [initial.centerXAnchor constraintEqualToAnchor:iconView.centerXAnchor],
      [initial.centerYAnchor constraintEqualToAnchor:iconView.centerYAnchor]
    ]];
  }
  UIStackView *identity =
      [[UIStackView alloc] initWithArrangedSubviews:@[ iconView, labels ]];
  identity.axis = UILayoutConstraintAxisHorizontal;
  identity.alignment = UIStackViewAlignmentCenter;
  identity.spacing = 12;
  UIButton *refresh = ipaRefreshButton(app);
  [refresh setContentHuggingPriority:UILayoutPriorityRequired
                             forAxis:UILayoutConstraintAxisHorizontal];
  [refresh
      setContentCompressionResistancePriority:UILayoutPriorityRequired
                                      forAxis:UILayoutConstraintAxisHorizontal];
  UIStackView *row =
      [[UIStackView alloc] initWithArrangedSubviews:@[ identity, refresh ]];
  row.axis =
      large ? UILayoutConstraintAxisVertical : UILayoutConstraintAxisHorizontal;
  row.alignment = large ? UIStackViewAlignmentFill : UIStackViewAlignmentCenter;
  row.spacing = 12;
  row.translatesAutoresizingMaskIntoConstraints = NO;
  cell.contentView.directionalLayoutMargins =
      NSDirectionalEdgeInsetsMake(16, 16, 16, 16);
  [cell.contentView addSubview:row];
  [NSLayoutConstraint activateConstraints:@[
    [row.topAnchor
        constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.topAnchor],
    [row.bottomAnchor
        constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                    .bottomAnchor],
    [row.leadingAnchor
        constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                    .leadingAnchor],
    [row.trailingAnchor
        constraintEqualToAnchor:cell.contentView.layoutMarginsGuide
                                    .trailingAnchor]
  ]];
  cell.isAccessibilityElement = NO;
  return cell;
}
- (void)tableView:(UITableView *)tableView
    didSelectRowAtIndexPath:(NSIndexPath *)path {
  [tableView deselectRowAtIndexPath:path animated:YES];
  if (path.row >= self.apps.count)
    return;
  [self showDetails:self.apps[path.row]];
}
- (void)showDetails:(NSDictionary *)app {
  IPALoaderAppDetails *details =
      [[IPALoaderAppDetails alloc] initWithStyle:UITableViewStyleInsetGrouped];
  details.app = app;
  [self.navigationController pushViewController:details animated:YES];
}
- (void)refreshApp:(NSDictionary *)snapshot {
  if (!ipaSignedIn || ipaWorking || ipaVPNBusy ||
      (ipaVPNRequired && !ipaVPNConnected))
    return;
  // Resolve the current record; a pull-to-refresh may have reordered the list.
  NSDictionary *app = nil;
  for (NSDictionary *candidate in self.apps)
    if ([candidate[@"BundleID"] isEqual:snapshot[@"BundleID"]]) {
      app = candidate;
      break;
    }
  if (!app)
    return;
  void (^refresh)(void) = ^{
    if (!ipaSignedIn || ipaWorking || ipaVPNBusy ||
        (ipaVPNRequired && !ipaVPNConnected))
      return;
    ipaWorking = YES;
    [self updateControls];
    ipa_go_apps_action((char *)[app[@"BundleID"] UTF8String]);
  };
  refresh();
}
@end

static void ipaApplyAuthentication(BOOL wasSignedIn) {
  if (!ipaTabs)
    return;
  [ipaApps updateControls];
  if (ipaSignedIn && !wasSignedIn && ipaTabs.selectedIndex == 1)
    ipaTabs.selectedIndex = 0;
  ipa_go_apps_load(0);
}
void ipa_ios_apps_authenticated(int authenticated) {
  dispatch_async(dispatch_get_main_queue(), ^{
    BOOL previous = ipaSignedIn;
    if (previous == (authenticated != 0))
      return;
    ipaSignedIn = authenticated != 0;
    ipaApplyAuthentication(previous);
  });
}
void ipa_ios_apps_busy(int busy) {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (ipaWorking == (busy != 0))
      return;
    ipaWorking = busy != 0;
    if (ipaApps.isViewLoaded) {
      [ipaApps updateControls];
      if (!ipaWorking && ipaApps.view.window && !ipaApps.checked)
        [ipaApps checkApps];
    }
  });
}
UIViewController *ipa_ios_make_root(void) {
  if (ipaTabs)
    return ipaTabs;
  ipaApps = [[IPALoaderApps alloc] initWithStyle:UITableViewStyleInsetGrouped];
  UINavigationController *navigation =
      [[UINavigationController alloc] initWithRootViewController:ipaApps];
  navigation.tabBarItem = [[UITabBarItem alloc]
      initWithTitle:@"Apps"
              image:[UIImage systemImageNamed:@"square.stack.3d.up"]
                tag:0];
  ipaAccountNavigation = ipa_ios_account_controller();
  ipaTabs = [IPALoaderTabs new];
  ipaTabs.viewControllers = @[ navigation, ipaAccountNavigation ];
  ipaTabs.tabBar.tintColor = UIColor.systemTealColor;
  ipaApplyAuthentication(ipaSignedIn);
  return ipaTabs;
}
void ipa_ios_apps_update(const char *json) {
  NSString *text = @(json);
  dispatch_async(dispatch_get_main_queue(), ^{
    NSDictionary *payload = [NSJSONSerialization
        JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding]
                   options:0
                     error:nil];
    if (![payload isKindOfClass:NSDictionary.class])
      return;
    [ipaApps.refreshControl endRefreshing];
    if ([ipaApps.apps isEqual:payload[@"Apps"]] &&
        [ipaApps.message isEqual:payload[@"Message"]])
      return;
    ipaApps.pendingPayload = payload;
    [ipaApps reloadWhenIdle];
  });
}

void ipa_ios_show_account(void) { ipaTabs.selectedIndex = 1; }
void ipa_ios_update_operation(NSDictionary *state) {
  BOOL controlsChanged =
      ipaVPNRequired != [state[@"VPNAvailable"] boolValue] ||
      ipaVPNConnected != [state[@"VPNConnected"] boolValue] ||
      ipaVPNBusy != [state[@"VPNBusy"] boolValue] ||
      ipaEligibleRefreshes != [state[@"EligibleRefreshes"] integerValue] ||
      ![ipaApps.operation[@"Busy"] isEqual:state[@"Busy"]] ||
      ![ipaApps.operation[@"Target"] isEqual:state[@"Target"]] ||
      ![ipaApps.operation[@"Operation"] isEqual:state[@"Operation"]];
  ipaVPNRequired = [state[@"VPNAvailable"] boolValue];
  ipaVPNConnected = [state[@"VPNConnected"] boolValue];
  ipaVPNBusy = [state[@"VPNBusy"] boolValue];
  ipaEligibleRefreshes = [state[@"EligibleRefreshes"] integerValue];
  ipaApps.operation = state;
  [ipaApps updateOperationSheet];
  if (controlsChanged)
    [ipaApps updateControls];
}
