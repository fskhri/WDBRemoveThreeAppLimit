#pragma once
@import Foundation;

@protocol TCCAccessRequest
- (void)requestAccessForService:(NSString *)service
                   withPurpose:(NSString *)purpose
                    preflight:(BOOL)preflight
                   completion:(void (^)(NSString *token, NSError *error))completion;
@end

/// Uses an alternative method for iOS 16.7.10 and CVE-2022-46689 for older versions to grant the current app read/write access outside the sandbox.
/// @param completion Called with nil on success, or an error on failure
void grant_full_disk_access(void (^_Nonnull completion)(NSError* _Nullable));

/// Attempts to patch installd for the current iOS version
/// @return true if successful, false otherwise
bool patch_installd(void);
