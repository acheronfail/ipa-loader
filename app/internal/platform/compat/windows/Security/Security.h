// Minimal independently declared public CoreFoundation/Security ABI used by
// compat/sharing.m. No implementation or Apple runtime binary is included.
#ifndef IPA_SHARING_SECURITY_H
#define IPA_SHARING_SECURITY_H
#include <stdint.h>
typedef int32_t OSStatus;
typedef const void *CFTypeRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef const struct __CFString *CFStringRef;
#define CF_RETURNS_RETAINED __attribute__((cf_returns_retained))
extern CFTypeRef CFRetain(CFTypeRef value);
extern void CFRelease(CFTypeRef value);
extern const CFStringRef kSecAttrAccessGroup;
static inline CFTypeRef CFBridgingRetain(id value) {
    return (__bridge_retained CFTypeRef)value;
}
#endif
