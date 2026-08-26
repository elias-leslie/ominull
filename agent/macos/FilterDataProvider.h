#import <NetworkExtension/NetworkExtension.h>

@interface FilterDataProvider : NEFilterDataProvider

@property (nonatomic, assign) BOOL isIsolated;
@property (nonatomic, strong) NSString *hubIP;
@property (nonatomic, assign) uint16_t hubPort;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *blockRules;

- (void)setIsolationMode:(BOOL)enable hubIP:(NSString *)ip port:(uint16_t)port;
- (void)addBlockRuleForIP:(NSString *)ip port:(uint16_t)port;
- (void)clearRules;

@end
