#ifndef helpers_h
#define helpers_h

#import <Foundation/Foundation.h>
#import <mach/mach.h>

#ifdef __cplusplus
extern "C" {
#endif

// Define PAGE_SIZE if not already defined
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x4000
#endif

// Helper functions for memory operations
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

// XPC helper functions
void xpc_crasher(const char* service_name);
bool overwrite_file(int fd, NSData* data);

// File helper functions
char* get_temp_file_path(void);
char* set_up_tmp_file(void);

// Utility macros
#define ROUND_DOWN_PAGE(val) ((val) & ~((mach_vm_size_t)PAGE_SIZE - 1ULL))

#ifdef __cplusplus
}
#endif

#endif /* helpers_h */
