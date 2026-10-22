#import <NetworkExtension/NetworkExtension.h>
#import <netinet/in.h>
#include "reflect.h"

@interface IPALoaderPacketTunnelProvider : NEPacketTunnelProvider
@property(atomic) BOOL running;
@end
@implementation IPALoaderPacketTunnelProvider
- (void)readNext {
 if(!self.running) return;
 __weak typeof(self) weakSelf=self;
 [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols){
  typeof(self) self=weakSelf;
  if(!self || !self.running) return;
  NSMutableArray *output=[NSMutableArray new], *families=[NSMutableArray new];
  for(NSUInteger i=0;i<packets.count;i++){
   if(i>=protocols.count || protocols[i].intValue!=AF_INET) continue;
   NSMutableData *packet=[packets[i] mutableCopy];
   if(ipa_reflect_packet(packet.mutableBytes,packet.length)){[output addObject:packet];[families addObject:@(AF_INET)];}
  }
  if(output.count) [self.packetFlow writePackets:output withProtocols:families];
  [self readNext];
 }];
}
- (void)startTunnelWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {
 NEPacketTunnelNetworkSettings *settings=[[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:@"10.7.0.1"];
 NEIPv4Settings *ipv4=[[NEIPv4Settings alloc] initWithAddresses:@[@"10.7.0.2"] subnetMasks:@[@"255.255.255.252"]];
 ipv4.includedRoutes=@[[[NEIPv4Route alloc] initWithDestinationAddress:@"10.7.0.1" subnetMask:@"255.255.255.255"]];
 ipv4.excludedRoutes=@[NEIPv4Route.defaultRoute];
 settings.IPv4Settings=ipv4;settings.MTU=@1500;
 [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error){
  if(!error){self.running=YES;[self readNext];}
  completionHandler(error);
 }];
}
- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
 self.running=NO;completionHandler();
}
@end
