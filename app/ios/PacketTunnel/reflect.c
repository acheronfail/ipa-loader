#include "reflect.h"
#include <string.h>
int ipa_reflect_packet(uint8_t *p, size_t n) {
 static const uint8_t local[4]={10,7,0,2}, peer[4]={10,7,0,1};
 if(n<20 || p[0]>>4!=4) return 0;
 size_t h=(p[0]&15)*4, total=((size_t)p[2]<<8)|p[3];
 if(h<20 || h>n || total!=n || total<h || memcmp(p+12,local,4) || memcmp(p+16,peer,4)) return 0;
 // IPv4 and transport pseudo-header checksums are unchanged by swapping the
 // two addresses: one's-complement addition is commutative. Fragments retain
 // their original identification and offsets and are reassembled by the OS.
 memcpy(p+12,peer,4); memcpy(p+16,local,4);
 return 1;
}
