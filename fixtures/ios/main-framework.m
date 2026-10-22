#import <UIKit/UIKit.h>
#include <stdio.h>
#include <stdlib.h>
extern int FixtureKitValue(void);
extern BOOL FixtureKitResourceOK(void);
#ifndef FIXTURE_VERSION
#define FIXTURE_VERSION "1"
#endif

@interface FrameworkDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation FrameworkDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    int value = FixtureKitValue();
    BOOL resource = FixtureKitResourceOK();
    printf("IPA_LOADER_FRAMEWORK build=%s value=%d resource=%s\n",
        FIXTURE_VERSION, value, resource ? "ok" : "failed");
    fflush(stdout);
    if ([NSProcessInfo.processInfo.arguments containsObject:@"--fixture-check"]) {
        exit(value == 42 && resource ? 0 : 1);
    }
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;
    UILabel *label = [UILabel new];
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.text = [NSString stringWithFormat:@"Framework Test · Build %s\nFramework → dylib: %d\nFramework resource: %@",
        FIXTURE_VERSION, value, resource ? @"OK" : @"FAILED"];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [controller.view addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.centerXAnchor constraintEqualToAnchor:controller.view.centerXAnchor],
        [label.centerYAnchor constraintEqualToAnchor:controller.view.centerYAnchor]
    ]];
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];
    return YES;
}
@end
int main(int argc, char **argv) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(FrameworkDelegate.class)); }
}
