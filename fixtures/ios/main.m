#import <UIKit/UIKit.h>
#include <stdio.h>

#ifndef FIXTURE_VERSION
#define FIXTURE_VERSION "1"
#endif

@interface FixtureController : UIViewController
@property(nonatomic, strong) UILabel *counterLabel;
@end

@implementation FixtureController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    UILabel *title = [UILabel new];
    title.text = @"IPA Loader Fixture";
    title.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle1];
    UILabel *version = [UILabel new];
    version.text = @"Build " @FIXTURE_VERSION;
    self.counterLabel = [UILabel new];
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:@"Increment saved counter" forState:UIControlStateNormal];
    [button addTarget:self action:@selector(increment) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:
        @[title, version, self.counterLabel, button]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 20;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:16],
        [stack.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-16]
    ]];
    [self updateCounter];
}
- (void)updateCounter {
    NSInteger count = [NSUserDefaults.standardUserDefaults integerForKey:@"fixture.counter"];
    self.counterLabel.text = [NSString stringWithFormat:@"Saved counter: %ld", (long)count];
}
- (void)increment {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setInteger:[defaults integerForKey:@"fixture.counter"] + 1 forKey:@"fixture.counter"];
    [self updateCounter];
}
@end

@interface FixtureDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation FixtureDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    if ([NSProcessInfo.processInfo.arguments containsObject:@"--fixture-increment"]) {
        [defaults setInteger:[defaults integerForKey:@"fixture.counter"] + 1 forKey:@"fixture.counter"];
    }
    printf("IPA_LOADER_FIXTURE build=%s counter=%ld\n", FIXTURE_VERSION,
           (long)[defaults integerForKey:@"fixture.counter"]);
    fflush(stdout);
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [FixtureController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(FixtureDelegate.class));
    }
}
