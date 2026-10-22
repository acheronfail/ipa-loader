//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <TargetConditionals.h>
#include <stdlib.h>
#include <string.h>

static NSDictionary *accountQuery(const char *service) {
    return @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
             (__bridge id)kSecAttrService: [NSString stringWithUTF8String:service],
             (__bridge id)kSecAttrAccount: @"sessions-v1"};
}

void *ipa_accounts_read(const char *service, int *length, int *status) {
    @autoreleasepool {
        *length = 0;
        NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:accountQuery(service)];
        query[(__bridge id)kSecReturnData] = @YES;
        query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
        CFTypeRef result = NULL;
        OSStatus code = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (code == errSecItemNotFound) { *status = 0; return NULL; }
        *status = (int)code;
        if (code != errSecSuccess) { if (result) CFRelease(result); return NULL; }
        if (!result || CFGetTypeID(result) != CFDataGetTypeID()) {
            if (result) CFRelease(result);
            *status = errSecDecode; return NULL;
        }
        CFIndex size = CFDataGetLength((CFDataRef)result);
        if (size <= 0 || size > 1048576) { CFRelease(result); *status = errSecDecode; return NULL; }
        void *copy = malloc((size_t)size);
        if (!copy) { CFRelease(result); *status = errSecAllocate; return NULL; }
        memcpy(copy, CFDataGetBytePtr((CFDataRef)result), (size_t)size);
        *length = (int)size;
        CFRelease(result);
        return copy;
    }
}

int ipa_accounts_write(const char *service, const void *data, int length) {
    @autoreleasepool {
        if (!data || length <= 0 || length > 1048576) return errSecParam;
        NSDictionary *values = @{(__bridge id)kSecValueData: [NSData dataWithBytes:data length:(NSUInteger)length]};
        OSStatus code = SecItemUpdate((__bridge CFDictionaryRef)accountQuery(service), (__bridge CFDictionaryRef)values);
        if (code == errSecItemNotFound) {
            NSMutableDictionary *item = [NSMutableDictionary dictionaryWithDictionary:accountQuery(service)];
            [item addEntriesFromDictionary:values];
#if TARGET_OS_IPHONE
            item[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
#endif
            item[(__bridge id)kSecAttrLabel] = @"IPA Loader saved Apple accounts";
            code = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
        }
        return (int)code;
    }
}

int ipa_accounts_delete(const char *service) {
    @autoreleasepool {
        OSStatus code = SecItemDelete((__bridge CFDictionaryRef)accountQuery(service));
        return code == errSecItemNotFound ? 0 : (int)code;
    }
}
