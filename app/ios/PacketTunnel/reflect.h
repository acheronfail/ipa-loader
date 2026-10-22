#ifndef IPA_REFLECT_H
#define IPA_REFLECT_H
#include <stddef.h>
#include <stdint.h>
// Reflect only outbound IPv4 packets on the private developer-service route.
int ipa_reflect_packet(uint8_t *packet, size_t size);
#endif
