// Minimal independently declared public ABI used by compat/sharing.m.
// Implementations are supplied by iOS Foundation; this is not an SDK replacement.
#ifndef IPA_SHARING_FOUNDATION_H
#define IPA_SHARING_FOUNDATION_H
#include <objc/NSObject.h>
#include <stddef.h>

@class NSString, NSURL;
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
@end
@interface NSUserDefaults : NSObject
- (instancetype)initWithSuiteName:(NSString *)name;
@end
#endif
