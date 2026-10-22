//go:build darwin && cgo && !ios

#import <AppKit/AppKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

char *ipa_choose_file(const char *current, uintptr_t parentHandle, int *failed) {
    __block char *selected = NULL;
    __block int error = 0;
    // Present asynchronously on AppKit's main queue. The worker waits for the
    // completion without nesting or blocking Fyne's native event loop.
    if ([NSThread isMainThread]) { *failed = 1; return NULL; }
    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    void (^show)(void) = ^{
        @autoreleasepool {
            @try {
                NSOpenPanel *panel = [NSOpenPanel openPanel];
                panel.title = @"Choose an IPA";
                panel.prompt = @"Choose";
                panel.canChooseFiles = YES;
                panel.canChooseDirectories = NO;
                panel.allowsMultipleSelection = NO;
                UTType *type = [UTType typeWithFilenameExtension:@"ipa"];
                if (type) panel.allowedContentTypes = @[type];
                NSString *previous = current ? [NSString stringWithUTF8String:current] : nil;
                if (previous.length) {
                    NSString *directory = [previous stringByDeletingLastPathComponent];
                    BOOL isDirectory = NO;
                    if ([[NSFileManager defaultManager] fileExistsAtPath:directory isDirectory:&isDirectory] && isDirectory) {
                        panel.directoryURL = [NSURL fileURLWithPath:directory isDirectory:YES];
                    }
                }
                [NSApp activateIgnoringOtherApps:YES];
                NSWindow *parent = (__bridge NSWindow *)(void *)parentHandle;
                void (^finish)(NSModalResponse) = ^(NSModalResponse response) {
                    if (response == NSModalResponseOK) {
                        const char *path = panel.URL.fileSystemRepresentation;
                        if (path) selected = strdup(path);
                        if (!selected) error = 1;
                    }
                    [panel orderOut:nil];
                    [parent makeKeyAndOrderFront:nil];
                    dispatch_semaphore_signal(completed);
                };
                if (parent) [panel beginSheetModalForWindow:parent completionHandler:finish];
                else [panel beginWithCompletionHandler:finish];
            } @catch (NSException *exception) { error = 1; dispatch_semaphore_signal(completed); }
        }
    };
    dispatch_async(dispatch_get_main_queue(), show);
    dispatch_semaphore_wait(completed, DISPATCH_TIME_FOREVER);
    *failed = error;
    return selected;
}
