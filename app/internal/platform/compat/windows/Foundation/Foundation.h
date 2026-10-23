// Minimal independently declared public ABI used by compat/sharing.m.
// Implementations are supplied by iOS Foundation; this is not an SDK replacement.
#ifndef IPA_SHARING_FOUNDATION_H
#define IPA_SHARING_FOUNDATION_H
#include <objc/NSObject.h>
#include <stddef.h>

@class NSString, NSURL, NSError;
typedef NSUInteger NSSearchPathDirectory;
typedef NSUInteger NSSearchPathDomainMask;
enum { NSApplicationSupportDirectory = 14, NSUserDomainMask = 1 };
typedef struct {
    unsigned long state;
    id __unsafe_unretained *itemsPtr;
    unsigned long *mutationsPtr;
    unsigned long extra[5];
} NSFastEnumerationState;
@protocol NSFastEnumeration
- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state
                                 objects:(id __unsafe_unretained [])objects
                                   count:(NSUInteger)count;
@end
@interface NSString : NSObject
@property (readonly) NSString *lastPathComponent;
- (BOOL)isEqualToString:(NSString *)other;
- (NSString *)stringByAppendingString:(NSString *)other;
@end
@interface NSArray<ObjectType> : NSObject
@property (readonly) ObjectType firstObject;
@end
@interface NSURL : NSObject
- (NSURL *)URLByAppendingPathComponent:(NSString *)path isDirectory:(BOOL)directory;
@end
@interface NSDictionary<KeyType, ObjectType> : NSObject <NSFastEnumeration>
+ (instancetype)dictionaryWithObjects:(const id [])objects
                              forKeys:(const id [])keys
                                count:(NSUInteger)count;
- (ObjectType)objectForKeyedSubscript:(KeyType)key;
@property (readonly) NSUInteger count;
@end
@interface NSMutableDictionary<KeyType, ObjectType> : NSDictionary<KeyType,ObjectType>
- (void)setObject:(ObjectType)object forKeyedSubscript:(KeyType)key;
@end
@interface NSBundle : NSObject
+ (NSBundle *)mainBundle;
- (id)objectForInfoDictionaryKey:(NSString *)key;
@end
@interface NSFileManager : NSObject
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)group;
- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domains;
- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)intermediates attributes:(NSDictionary *)attributes error:(NSError **)error;
@end
@interface NSUserDefaults : NSObject
- (instancetype)initWithSuiteName:(NSString *)name;
@end
#endif
