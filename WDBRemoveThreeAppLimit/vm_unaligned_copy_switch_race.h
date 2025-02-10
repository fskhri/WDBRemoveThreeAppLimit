#ifndef vm_unaligned_copy_switch_race_h
#define vm_unaligned_copy_switch_race_h

#import <Foundation/Foundation.h>

/**
 * Performs a race condition exploit to write data to a file descriptor
 * @param fd File descriptor to write to
 * @param offset Offset in the file to write at
 * @param data Data to write
 * @param length Length of data to write (must be <= PAGE_SIZE)
 * @return true if successful, false otherwise
 */
FOUNDATION_EXTERN bool unaligned_copy_switch_race(int fd, off_t offset, const void* data, size_t length);

#endif /* vm_unaligned_copy_switch_race_h */
