#import "FilterDataProvider.h"

@implementation FilterDataProvider

- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable))completionHandler {
    self.blockRules = [NSMutableArray array];
    self.isIsolated = NO;
    NSLog(@"[+] Ominull NetworkExtension Provider started successfully.");
    completionHandler(nil);
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    NSLog(@"[*] Ominull NetworkExtension Provider stopping (Reason: %ld)", (long)reason);
    completionHandler();
}

- (void)setIsolationMode:(BOOL)enable hubIP:(NSString *)ip port:(uint16_t)port {
    self.isIsolated = enable;
    self.hubIP = ip;
    self.hubPort = port;
    NSLog(@"[*] Ominull Isolation Mode set to %d (Hub: %@:%u)", enable, ip, port);
}

- (void)addBlockRuleForIP:(NSString *)ip port:(uint16_t)port {
    [self.blockRules addObject:@{@"ip": ip, @"port": @(port)}];
    NSLog(@"[*] Ominull Added Block Rule for %@:%u", ip, port);
}

- (void)clearRules {
    [self.blockRules removeAllObjects];
    NSLog(@"[*] Ominull Cleared all filter rules.");
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if ([flow isKindOfClass:[NEFilterSocketFlow class]]) {
        NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
        NWEndpoint *remoteEndpoint = socketFlow.remoteEndpoint;

        if ([remoteEndpoint isKindOfClass:[NWHostEndpoint class]]) {
            NWHostEndpoint *hostEndpoint = (NWHostEndpoint *)remoteEndpoint;
            NSString *remoteIP = hostEndpoint.hostname;
            uint16_t remotePort = (uint16_t)[hostEndpoint.port integerValue];

            // 1. Check Kernel Host Isolation
            if (self.isIsolated) {
                // Allow Loopback
                if ([remoteIP isEqualToString:@"127.0.0.1"] || [remoteIP isEqualToString:@"::1"] || [remoteIP hasPrefix:@"127."]) {
                    return [NEFilterNewFlowVerdict allowVerdict];
                }

                // Allow Hub
                if (self.hubIP && [remoteIP isEqualToString:self.hubIP]) {
                    if (self.hubPort == 0 || remotePort == self.hubPort) {
                        return [NEFilterNewFlowVerdict allowVerdict];
                    }
                }

                // Allow DHCP & DNS
                if (remotePort == 53 || remotePort == 67 || remotePort == 68) {
                    return [NEFilterNewFlowVerdict allowVerdict];
                }

                NSLog(@"[-] [ISOLATION] Dropped unauthorized connection to %@:%u", remoteIP, remotePort);
                return [NEFilterNewFlowVerdict dropVerdict];
            }

            // 2. Check Dynamic Block Rules
            for (NSDictionary *rule in self.blockRules) {
                NSString *targetIP = rule[@"ip"];
                uint16_t targetPort = [rule[@"port"] unsignedShortValue];

                if ([remoteIP isEqualToString:targetIP] && (targetPort == 0 || remotePort == targetPort)) {
                    NSLog(@"[-] [BLOCK] Blocked connection to %@:%u matching rule", remoteIP, remotePort);
                    return [NEFilterNewFlowVerdict dropVerdict];
                }
            }
        }
    }

    return [NEFilterNewFlowVerdict allowVerdict];
}

@end
