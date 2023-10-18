#import "GhidraCommunicator.h"

CFReadStreamRef readStream;
CFWriteStreamRef writeStream;
NSOutputStream *outputStream;

@implementation GhidraCommunicator

- (void)open {
    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, (CFStringRef)@"127.0.0.1", 5740, &readStream, &writeStream);

    if(!CFWriteStreamOpen(writeStream)) {
        NSLog(@"Failed to open writeStream");
        return;
    }

    outputStream = (NSOutputStream *)writeStream;
    [outputStream retain];
    [outputStream setDelegate:self];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
}

- (void)close {
    [outputStream close];
    [outputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream release];
    outputStream = nil;
}

- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)streamEvent {
    switch(streamEvent) {
        case NSStreamEventErrorOccurred:
            NSLog(@"Cannot connect to Ghidra");
        case NSStreamEventEndEncountered:
            [self close];
        default:
            return;
    }
}

- (void)sendToGhidra:(NSString *)url {
    [self open];

    uint8_t *buf = (uint8_t *)[[url stringByAppendingString:@"\n"] UTF8String];
    NSLog(@"Attempt to send to Ghidra");
    [outputStream write:buf maxLength:strlen((char *)buf)];

    [self close];
}

@end