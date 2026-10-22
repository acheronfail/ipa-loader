//go:build ios
#import <UIKit/UIKit.h>
#import "controls_ios.h"
#include <stdlib.h>

@interface IPALoaderChoice : UITableViewController <UIAdaptivePresentationControllerDelegate>
@property(nonatomic,copy) NSArray<NSString *> *options;
@property(nonatomic) NSInteger selected;
@property(nonatomic) NSInteger result;
@property(nonatomic) BOOL finished;
@property(nonatomic) dispatch_semaphore_t done;
@end
@implementation IPALoaderChoice
- (void)viewDidLoad {
 [super viewDidLoad];
 self.tableView.rowHeight=UITableViewAutomaticDimension;
 self.tableView.estimatedRowHeight=56;
 self.navigationItem.leftBarButtonItem=ipa_ios_bar_button(@"Cancel",self,@selector(cancel),NO);
}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return self.options.count; }
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
 UITableViewCell *cell=[tableView dequeueReusableCellWithIdentifier:@"choice"];
 if(!cell) cell=[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"choice"];
 cell.textLabel.text=self.options[path.row];
 cell.textLabel.font=[UIFont preferredFontForTextStyle:UIFontTextStyleBody];
 cell.textLabel.adjustsFontForContentSizeCategory=YES;
 cell.textLabel.numberOfLines=0;
 cell.accessoryType=path.row==self.selected?UITableViewCellAccessoryCheckmark:UITableViewCellAccessoryNone;
 cell.accessibilityTraits=UIAccessibilityTraitButton | (path.row==self.selected?UIAccessibilityTraitSelected:0);
 return cell;
}
- (void)finish:(NSInteger)result {
 if(self.finished) return;
 self.finished=YES;self.result=result;
 dispatch_semaphore_signal(self.done);
}
- (void)cancel { [self dismissViewControllerAnimated:YES completion:^{[self finish:-1];}]; }
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
 [self dismissViewControllerAnimated:YES completion:^{[self finish:path.row];}];
}
- (void)presentationControllerDidDismiss:(UIPresentationController *)controller { [self finish:-1]; }
@end

// UIKit owns the presented controller while a Go worker waits. Interactive
// dismissal and Cancel are both cancellation, and selecting the current row is
// still an explicit selection. No UI thread is blocked by the bridge.
int ipa_ios_choose_option(const char *title, const char *json, int selected) {
 if(NSThread.isMainThread) return -2;
 @autoreleasepool {
 NSData *data=[@(json) dataUsingEncoding:NSUTF8StringEncoding];
 NSArray *options=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
 if(![options isKindOfClass:NSArray.class] || options.count==0) return -2;
 for(id option in options) if(![option isKindOfClass:NSString.class]) return -2;
 IPALoaderChoice *choice=[[IPALoaderChoice alloc] initWithStyle:UITableViewStyleInsetGrouped];
 choice.options=options;choice.selected=selected;choice.result=-1;choice.done=dispatch_semaphore_create(0);
 NSString *heading=@(title);
 dispatch_async(dispatch_get_main_queue(),^{
  UIViewController *root=nil;
  for(UIScene *scene in UIApplication.sharedApplication.connectedScenes){
   if(scene.activationState!=UISceneActivationStateForegroundActive || ![scene isKindOfClass:UIWindowScene.class]) continue;
   for(UIWindow *window in ((UIWindowScene *)scene).windows) if(window.isKeyWindow){root=window.rootViewController;break;}
   if(root) break;
  }
  if(!root){[choice finish:-2];return;}
  while(root.presentedViewController) root=root.presentedViewController;
  [root.view endEditing:YES];
  choice.title=heading;
  UINavigationController *navigation=[[UINavigationController alloc] initWithRootViewController:choice];
  navigation.modalPresentationStyle=UIModalPresentationPageSheet;
  if(@available(iOS 15.0,*)){
   navigation.sheetPresentationController.detents=@[UISheetPresentationControllerDetent.mediumDetent,UISheetPresentationControllerDetent.largeDetent];
   navigation.sheetPresentationController.prefersGrabberVisible=YES;
  }
  navigation.presentationController.delegate=choice;
  [root presentViewController:navigation animated:YES completion:^{
   if(choice.selected>=0 && choice.selected<choice.options.count) [choice.tableView scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:choice.selected inSection:0] atScrollPosition:UITableViewScrollPositionMiddle animated:NO];
  }];
 });
 dispatch_semaphore_wait(choice.done,DISPATCH_TIME_FOREVER);
 return (int)choice.result;
 }
}
