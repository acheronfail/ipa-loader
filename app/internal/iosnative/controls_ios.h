#import <UIKit/UIKit.h>
UIBarButtonItem *ipa_ios_bar_button(NSString *title, id target, SEL action,
                                    BOOL primary);
// Finish a presentation transition before a worker can open its next sheet.
void ipa_ios_dismiss(UIViewController *controller, dispatch_block_t completion);

UIImageView *ipa_ios_app_icon(UIImage *image, CGFloat size);
