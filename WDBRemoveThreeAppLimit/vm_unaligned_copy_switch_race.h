#pragma once
#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Performs a race condition exploit to write data to a file descriptor
/// @param fd File descriptor to write to
/// @param offset Offset in the file to write at
/// @param data Data to write
/// @param length Length of data to write (must be <= PAGE_SIZE)
/// @return true if successful, false otherwise
__attribute__((visibility("default")))
bool unaligned_copy_switch_race(int fd, off_t offset, const void* data, size_t length);

#ifdef __cplusplus
}
#endif
