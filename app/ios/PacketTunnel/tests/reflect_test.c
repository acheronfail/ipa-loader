#include "../reflect.h"
#include <assert.h>
#include <string.h>
static unsigned sum(const unsigned char *p,size_t n){unsigned s=0;for(size_t i=0;i<n;i+=2)s+=(p[i]<<8)|(i+1<n?p[i+1]:0);while(s>>16)s=(s&65535)+(s>>16);return s;}
int main(void){
 unsigned char p[40]={0x45,0,0,40,0,1,0,0,64,6,0,0,10,7,0,2,10,7,0,1,0x12,0x34,0x56,0x78};
 unsigned before=sum(p,sizeof p),pseudo=sum(p+12,8);
 assert(ipa_reflect_packet(p,sizeof p));assert(sum(p,sizeof p)==before);assert(sum(p+12,8)==pseudo);
 assert(p[15]==1 && p[19]==2);
 unsigned char saved[40];memcpy(saved,p,40);
 assert(!ipa_reflect_packet(p,40));assert(!memcmp(saved,p,40));
 assert(!ipa_reflect_packet(p,19));
 memcpy(p+12,(unsigned char[]){10,7,0,2},4);memcpy(p+16,(unsigned char[]){10,7,0,1},4);
 p[0]=0x44;assert(!ipa_reflect_packet(p,40));p[0]=0x4f;assert(!ipa_reflect_packet(p,40));p[0]=0x45;
 p[3]=41;assert(!ipa_reflect_packet(p,40));p[3]=40;p[16]=8;assert(!ipa_reflect_packet(p,40));
 return 0;
}
