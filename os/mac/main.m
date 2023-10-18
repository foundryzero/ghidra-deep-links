#import <Cocoa/Cocoa.h>
#import "AppDelegate.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        AppDelegate *delegate = [[AppDelegate alloc] init];
        NSApplication *app = [NSApplication sharedApplication];
        app.delegate = delegate;
        NSLog(@"Starting GhidraDeepLinksHandler");
        NSApplicationMain(argc, argv);
    }
}
