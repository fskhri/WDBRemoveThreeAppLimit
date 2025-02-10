#import "vm_unaligned_copy_switch_race.h"
#import <mach/mach.h>
#import <pthread.h>
#import <sys/mman.h>

#define PAGE_SIZE 0x4000

__attribute__((visibility("default")))
bool unaligned_copy_switch_race(int fd, off_t offset, const void* data, size_t length) {
    if (!data || length == 0 || length > PAGE_SIZE) {
        return false;
    }
    
    void *buffer = mmap(NULL, PAGE_SIZE * 2, 
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);
                      
    if (buffer == MAP_FAILED) {
        return false;
    }
    
    // Copy data to buffer
    memcpy(buffer, data, length);
    
    // Protect first page
    if (mprotect(buffer, PAGE_SIZE, PROT_READ) != 0) {
        munmap(buffer, PAGE_SIZE * 2);
        return false;
    }
    
    // Write to file
    ssize_t written = pwrite(fd, buffer, length, offset);
    
    // Clean up
    munmap(buffer, PAGE_SIZE * 2);
    
    return written == length;
} 