#import <Cocoa/Cocoa.h>

@interface GhidraCommunicator : NSObject <NSStreamDelegate>

- (void)open;
- (void)close;
- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)streamEvent;
- (void)sendToGhidra:(NSString *)url;

@end
