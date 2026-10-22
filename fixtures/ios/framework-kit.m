#import <Foundation/Foundation.h>
extern int FixtureMathValue(void);

@interface FixtureKit : NSObject
@end
@implementation FixtureKit
@end

int FixtureKitValue(void) { return FixtureMathValue() + 2; }
BOOL FixtureKitResourceOK(void) {
    NSBundle *bundle = [NSBundle bundleForClass:FixtureKit.class];
    NSString *path = [bundle pathForResource:@"proof" ofType:@"txt"];
    NSString *value = path ? [NSString stringWithContentsOfFile:path
        encoding:NSUTF8StringEncoding error:nil] : nil;
    return [value isEqualToString:@"framework-resource-ok\n"];
}
