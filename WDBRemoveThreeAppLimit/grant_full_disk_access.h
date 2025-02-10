#pragma once
@import Foundation;
#import <sqlite3.h>

/// Uses CVE-2022-46689 to grant the current app read/write access outside the sandbox.
void grant_full_disk_access(void (^_Nonnull completion)(NSError* _Nullable error));
bool patch_installd(void);
