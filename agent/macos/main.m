#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "FilterDataProvider.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"===============================================================================");
        NSLog(@"      OMINULL MACOS THREAT NULLIFICATION ENGINE (NetworkExtension)");
        NSLog(@"===============================================================================");
        NSLog(@"[+] Initializing NEFilterDataProvider subsystem...");
        
        [NEProvider startSystemExtensionMode];
        dispatch_main();
    }
    return 0;
}
