#import "AppDelegate.h"
#import "GhidraCommunicator.h"

@implementation AppDelegate

- (void)handleURLEvent:(NSAppleEventDescriptor *)event
        withReplyEvent:(NSAppleEventDescriptor *)replyEvent {
    NSString *url = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
    NSLog(@"Got URL: %@", url);

    GhidraCommunicator *communicator = [[GhidraCommunicator alloc] init];
    [communicator sendToGhidra:url];

    exit(0);
}

- (void)applicationWillFinishLaunching:(NSNotification *)aNotification {
    [[NSAppleEventManager sharedAppleEventManager] setEventHandler:self
        andSelector:@selector(handleURLEvent:withReplyEvent:)
        forEventClass:kInternetEventClass
        andEventID:kAEGetURL];
    NSLog(@"GhidraDeepLinksHandler Started");
}

@end
