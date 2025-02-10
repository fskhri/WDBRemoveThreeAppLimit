#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Performs a race condition exploit to write data to a file descriptor
/// @param fd File descriptor to write to
/// @param offset Offset in the file to write at
/// @param data Data to write (must not be NULL)
/// @param length Length of data to write (must be <= PAGE_SIZE and > 0)
/// @return true if successful, false otherwise
bool unaligned_copy_switch_race(int fd, off_t offset, const void* _Nonnull data, size_t length);

NS_ASSUME_NONNULL_END
