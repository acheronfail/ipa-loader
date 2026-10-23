#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include "fishhook.h"

static NSDictionary<NSString *,NSString *> *appAliases;
static NSDictionary<NSString *,NSString *> *localAppGroups;
static NSDictionary<NSString *,NSString *> *keychainAliases;
static OSStatus (*originalAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*originalCopy)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*originalUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*originalDelete)(CFDictionaryRef);

static NSDictionary *safeAliases(id value) {
    if (![value isKindOfClass:NSDictionary.class]) return @{};
    for (id key in value) {
        if (![key isKindOfClass:NSString.class] || ![value[key] isKindOfClass:NSString.class]) return @{};
    }
    return value;
}

@interface NSFileManager (IPALoaderSharing)
- (NSURL *)ipa_containerURLForSecurityApplicationGroupIdentifier:(NSString *)group;
@end
@implementation NSFileManager (IPALoaderSharing)
- (NSURL *)ipa_containerURLForSecurityApplicationGroupIdentifier:(NSString *)group {
    NSString *local = group ? localAppGroups[group] : nil;
    if (local) {
        // Personal Teams cannot authorize app groups. Give the containing app
        // a stable directory in its own sandbox without claiming shared access.
        if (![local.lastPathComponent isEqualToString:local] || [local isEqualToString:@"."] || [local isEqualToString:@".."]) return nil;
        NSURL *root = [[self URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
        if (!root) return nil;
        NSURL *directory = [[root URLByAppendingPathComponent:@"IPALoaderAppGroups" isDirectory:YES] URLByAppendingPathComponent:local isDirectory:YES];
        if (![self createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:nil error:NULL]) return nil;
        return directory;
    }
    return [self ipa_containerURLForSecurityApplicationGroupIdentifier:(group ? appAliases[group] : nil) ?: group];
}
@end

@interface NSUserDefaults (IPALoaderSharing)
- (instancetype)ipa_initWithSuiteName:(NSString *)name __attribute__((objc_method_family(init)));
@end
@implementation NSUserDefaults (IPALoaderSharing)
- (instancetype)ipa_initWithSuiteName:(NSString *)name {
    NSString *local = name ? localAppGroups[name] : nil;
    if (local) return [self ipa_initWithSuiteName:[@"org.ipaloader.localgroup." stringByAppendingString:local]];
    return [self ipa_initWithSuiteName:(name ? appAliases[name] : nil) ?: name];
}
@end

// Construct a new dictionary only when an explicitly requested group changes.
// Callers' queries, services, values and output buffers are never logged.
static CFDictionaryRef mappedQuery(CFDictionaryRef query) CF_RETURNS_RETAINED {
    if (!query) return NULL;
    NSDictionary *dictionary = (__bridge NSDictionary *)query;
    id old = dictionary[(__bridge id)kSecAttrAccessGroup];
    NSString *mapped = [old isKindOfClass:NSString.class] ? keychainAliases[old] : nil;
    if (!mapped) return CFRetain(query);
    NSMutableDictionary *result = dictionary.mutableCopy;
    result[(__bridge id)kSecAttrAccessGroup] = mapped;
    return CFBridgingRetain(result);
}

static OSStatus mappedAdd(CFDictionaryRef query,CFTypeRef *result) {
    CFDictionaryRef copy = mappedQuery(query);
    OSStatus status = originalAdd(copy,result);
    if (copy) CFRelease(copy);
    return status;
}
static OSStatus mappedCopy(CFDictionaryRef query,CFTypeRef *result) {
    CFDictionaryRef copy = mappedQuery(query);
    OSStatus status = originalCopy(copy,result);
    if (copy) CFRelease(copy);
    return status;
}
static OSStatus mappedUpdate(CFDictionaryRef query,CFDictionaryRef attributes) {
    CFDictionaryRef copy = mappedQuery(query), values = mappedQuery(attributes);
    OSStatus status = originalUpdate(copy,values);
    if (copy) CFRelease(copy);
    if (values) CFRelease(values);
    return status;
}
static OSStatus mappedDelete(CFDictionaryRef query) {
    CFDictionaryRef copy = mappedQuery(query);
    OSStatus status = originalDelete(copy);
    if (copy) CFRelease(copy);
    return status;
}

__attribute__((constructor)) static void initializeSharing(void) {
    @autoreleasepool {
        id metadata = [NSBundle.mainBundle objectForInfoDictionaryKey:@"IPALoaderSharing"];
        if (![metadata isKindOfClass:NSDictionary.class]) return;
        appAliases = safeAliases(metadata[@"AppGroups"]);
        localAppGroups = safeAliases(metadata[@"LocalAppGroups"]);
        keychainAliases = safeAliases(metadata[@"KeychainGroups"]);
        if (appAliases.count || localAppGroups.count) {
            method_exchangeImplementations(
                class_getInstanceMethod(NSFileManager.class,@selector(containerURLForSecurityApplicationGroupIdentifier:)),
                class_getInstanceMethod(NSFileManager.class,@selector(ipa_containerURLForSecurityApplicationGroupIdentifier:)));
            method_exchangeImplementations(
                class_getInstanceMethod(NSUserDefaults.class,@selector(initWithSuiteName:)),
                class_getInstanceMethod(NSUserDefaults.class,@selector(ipa_initWithSuiteName:)));
        }
        if (!keychainAliases.count) return;
        originalAdd = dlsym(RTLD_DEFAULT,"SecItemAdd");
        originalCopy = dlsym(RTLD_DEFAULT,"SecItemCopyMatching");
        originalUpdate = dlsym(RTLD_DEFAULT,"SecItemUpdate");
        originalDelete = dlsym(RTLD_DEFAULT,"SecItemDelete");
        if (!originalAdd || !originalCopy || !originalUpdate || !originalDelete) return;
        struct rebinding bindings[] = {
            {"SecItemAdd",mappedAdd,NULL}, {"SecItemCopyMatching",mappedCopy,NULL},
            {"SecItemUpdate",mappedUpdate,NULL}, {"SecItemDelete",mappedDelete,NULL}
        };
        rebind_symbols(bindings,sizeof(bindings)/sizeof(bindings[0]));
    }
}
