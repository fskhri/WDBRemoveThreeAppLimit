#import "vm_unaligned_copy_switch_race.h"
#import <mach/mach.h>
#import <pthread.h>
#import <sys/mman.h>

#define PAGE_SIZE 0x4000
#define VM_FLAGS_FIXED 0x0000

NS_ASSUME_NONNULL_BEGIN

bool unaligned_copy_switch_race(int fd, off_t offset, const void* data, size_t length) {
    if (!data || length == 0 || length > PAGE_SIZE) {
        return false;
    }
    
    @try {
        // Map memory for the copy with proper alignment
        void *buffer = mmap(NULL, PAGE_SIZE * 2, 
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                          -1, 0);
                          
        if (buffer == MAP_FAILED) {
            return false;
        }
        
        // Ensure proper alignment
        uintptr_t page_aligned = ((uintptr_t)buffer + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        void *aligned_buffer = (void *)page_aligned;
        
        // Copy data to buffer with bounds checking
        if (length > 0) {
            memcpy(aligned_buffer, data, length);
        }
        
        // Protect first page with proper error handling
        if (mprotect(aligned_buffer, PAGE_SIZE, PROT_READ) != 0) {
            munmap(buffer, PAGE_SIZE * 2);
            return false;
        }
        
        // Write to file with error checking
        ssize_t written = pwrite(fd, aligned_buffer, length, offset);
        
        // Clean up
        munmap(buffer, PAGE_SIZE * 2);
        
        return written == length;
    } @catch (NSException *exception) {
        NSLog(@"Exception in unaligned_copy_switch_race: %@", exception);
        return false;
    }
} 

NS_ASSUME_NONNULL_END 