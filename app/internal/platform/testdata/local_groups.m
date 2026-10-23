#import "../compat/sharing.m"

// Exercise the adapter against Foundation while directing every file write to
// the test workspace, independently of any user's application data.
static NSURL *workspace;
@interface TestFileManager : NSFileManager
@end
@implementation TestFileManager
- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domains {
    return @[workspace];
}
@end

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 2) return 1;
        workspace = [NSURL fileURLWithPath:[NSString stringWithUTF8String:argv[1]] isDirectory:YES];
        localAppGroups = @{@"group.example.youtube": @"group.example.youtube.TEAM"};
        TestFileManager *manager = [TestFileManager new];
        NSURL *first = [manager ipa_containerURLForSecurityApplicationGroupIdentifier:@"group.example.youtube"];
        NSURL *again = [manager ipa_containerURLForSecurityApplicationGroupIdentifier:@"group.example.youtube"];
        NSURL *expected = [[workspace URLByAppendingPathComponent:@"IPALoaderAppGroups" isDirectory:YES] URLByAppendingPathComponent:@"group.example.youtube.TEAM" isDirectory:YES];
        if (![first isEqual:expected] || ![again isEqual:first]) return 2;
        BOOL directory = NO;
        if (![manager fileExistsAtPath:first.path isDirectory:&directory] || !directory) return 3;
        localAppGroups = @{@"group.example.youtube": @"../escape"};
        if ([manager ipa_containerURLForSecurityApplicationGroupIdentifier:@"group.example.youtube"]) return 4;
        return 0;
    }
}
