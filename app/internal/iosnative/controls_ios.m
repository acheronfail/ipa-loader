//go:build ios
#import "controls_ios.h"

// Give navigation actions a visible padded surface as well as a 44-point hit
// target. UIKit's standard text bar items are easy to overlook on a phone.
UIBarButtonItem *ipa_ios_bar_button(NSString *title, id target, SEL action,
                                    BOOL primary) {
  UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
  UIButtonConfiguration *configuration =
      primary ? UIButtonConfiguration.filledButtonConfiguration
              : UIButtonConfiguration.tintedButtonConfiguration;
  configuration.title = title;
  configuration.contentInsets = NSDirectionalEdgeInsetsMake(10, 16, 10, 16);
  configuration.cornerStyle = UIButtonConfigurationCornerStyleCapsule;
  button.configuration = configuration;
  [button addTarget:target
                action:action
      forControlEvents:UIControlEventTouchUpInside];
  [button.heightAnchor constraintGreaterThanOrEqualToConstant:44].active = YES;
  [button.widthAnchor constraintGreaterThanOrEqualToConstant:64].active = YES;
  [button sizeToFit];
  return [[UIBarButtonItem alloc] initWithCustomView:button];
}

void ipa_ios_dismiss(UIViewController *controller,
                     dispatch_block_t completion) {
  if (!controller.presentingViewController) {
    dispatch_async(dispatch_get_main_queue(), completion);
    return;
  }
  if (controller.isBeingDismissed && controller.transitionCoordinator) {
    [controller.transitionCoordinator
        animateAlongsideTransition:nil
                        completion:^(
                            id<UIViewControllerTransitionCoordinatorContext>
                                context) {
                          completion();
                        }];
  } else {
    [controller dismissViewControllerAnimated:YES completion:completion];
  }
}

// Source PNG dimensions must never determine a row's layout.
UIImageView *ipa_ios_app_icon(UIImage *image, CGFloat size) {
  UIImageView *view = [[UIImageView alloc] initWithImage:image];
  view.contentMode = UIViewContentModeScaleAspectFill;
  view.layer.cornerRadius = size * 0.225;
  view.layer.cornerCurve = kCACornerCurveContinuous;
  view.clipsToBounds = YES;
  view.tintColor = UIColor.systemTealColor;
  view.isAccessibilityElement = NO;
  view.accessibilityElementsHidden = YES;
  [NSLayoutConstraint activateConstraints:@[
    [view.widthAnchor constraintEqualToConstant:size],
    [view.heightAnchor constraintEqualToConstant:size]
  ]];
  return view;
}
