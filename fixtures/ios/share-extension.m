#import <UIKit/UIKit.h>
#include <stdio.h>

@interface LoaderShareController : UIViewController
@end
@implementation LoaderShareController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    NSString *bundle = NSBundle.mainBundle.bundleIdentifier;
    NSString *build = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"];
    printf("IPA_LOADER_EXTENSION build=%s loaded=ok\n",build.UTF8String);
    fflush(stdout);
    NSDictionary *proof = @{ @"extension_executed":@YES, @"build":build, @"bundle_id":bundle };
    NSURL *documents = [NSFileManager.defaultManager URLForDirectory:NSDocumentDirectory
        inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:nil];
    NSData *data = [NSJSONSerialization dataWithJSONObject:proof options:0 error:nil];
    [data writeToURL:[documents URLByAppendingPathComponent:@"extension-proof.json"] atomically:YES];
    UILabel *label = [UILabel new];
    label.text = @"IPA Loader extension ran successfully";
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.accessibilityIdentifier = @"extension-runtime-success";
    UIButton *done = [UIButton buttonWithType:UIButtonTypeSystem];
    [done setTitle:@"Finish extension test" forState:UIControlStateNormal];
    [done addTarget:self action:@selector(finish) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[label,done]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 24;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [stack.widthAnchor constraintLessThanOrEqualToAnchor:self.view.widthAnchor multiplier:0.85]
    ]];
}
- (void)finish {
    NSExtensionItem *result = [NSExtensionItem new];
    result.attributedContentText = [[NSAttributedString alloc] initWithString:@"IPA_LOADER_EXTENSION_OK"];
    result.attachments = @[[[NSItemProvider alloc] initWithItem:@"IPA_LOADER_EXTENSION_OK" typeIdentifier:@"public.plain-text"]];
    [self.extensionContext completeRequestReturningItems:@[result] completionHandler:nil];
}
@end
