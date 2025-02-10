#pragma once
#import <Foundation/Foundation.h>

/// Uses CVE-2022-46689 to overwrite `overwrite_length` bytes of `file_to_overwrite` with `overwrite_data`, starting from `file_offset`.
/// `file_to_overwrite` should be a file descriptor opened with O_RDONLY.
/// `overwrite_length` must be less than or equal to `PAGE_SIZE`.
/// Returns `true` if the overwrite succeeded, and `false` if the device is not vulnerable.
bool unaligned_copy_switch_race(int fd, off_t offset, const void* data, size_t length);
