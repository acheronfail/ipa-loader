#import <UIKit/UIKit.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef FIXTURE_VERSION
#define FIXTURE_VERSION "1"
#endif

@interface ExtensionTestController : UIViewController
@property(nonatomic,strong) UILabel *status;
@end
@implementation ExtensionTestController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.status = [UILabel new];
    self.status.text = @"Extension fixture · Build " @FIXTURE_VERSION;
    self.status.numberOfLines = 0;
    self.status.textAlignment = NSTextAlignmentCenter;
    UIButton *share = [UIButton buttonWithType:UIButtonTypeSystem];
    [share setTitle:@"Test share extension" forState:UIControlStateNormal];
    [share addTarget:self action:@selector(share:) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[self.status,share]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 24;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor]
    ]];
}
- (void)share:(UIButton *)button {
    UIActivityViewController *activity = [[UIActivityViewController alloc]
        initWithActivityItems:@[@"IPA Loader extension test"] applicationActivities:nil];
    activity.popoverPresentationController.sourceView = button;
    activity.completionWithItemsHandler = ^(UIActivityType type, BOOL completed, NSArray *items, NSError *error) {
        self.status.text = completed ? @"Share extension completed" : @"Ready to test again";
    };
    [self presentViewController:activity animated:YES completion:nil];
}
@end

@interface ExtensionTestDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic,strong) UIWindow *window;
@end
@implementation ExtensionTestDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    NSArray *extensions = [NSFileManager.defaultManager contentsOfDirectoryAtPath:
        [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"PlugIns"] error:nil];
    BOOL exists = [extensions containsObject:@"LoaderShare.appex"];
    printf("IPA_LOADER_EXTENSION_HOST build=%s embedded=%s\n",FIXTURE_VERSION,exists ? "ok" : "missing");
    fflush(stdout);
    if ([NSProcessInfo.processInfo.arguments containsObject:@"--fixture-check"]) exit(exists ? 0 : 1);
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [ExtensionTestController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end
int main(int argc,char **argv) {
    @autoreleasepool {return UIApplicationMain(argc,argv,nil,NSStringFromClass(ExtensionTestDelegate.class));}
}
