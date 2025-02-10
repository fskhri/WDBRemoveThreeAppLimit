#import "vm_unaligned_copy_switch_race.h"
#import <mach/mach.h>
#import <pthread.h>

bool unaligned_copy_switch_race(int fd, off_t offset, const void* data, size_t length) {
    if (length > PAGE_SIZE) return false;
    
    // Set up the race condition
    vm_address_t target_map = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &target_map, PAGE_SIZE * 2, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return false;
    
    // Copy data to target
    memcpy((void*)target_map, data, length);
    
    // Set up protection
    kr = vm_protect(mach_task_self(), target_map, PAGE_SIZE, TRUE, VM_PROT_READ);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), target_map, PAGE_SIZE * 2);
        return false;
    }
    
    // Try to write
    if (pwrite(fd, (void*)target_map, length, offset) != length) {
        vm_deallocate(mach_task_self(), target_map, PAGE_SIZE * 2);
        return false;
    }
    
    vm_deallocate(mach_task_self(), target_map, PAGE_SIZE * 2);
    return true;
} 