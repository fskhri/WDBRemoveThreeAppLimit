#pragma once
@import Foundation;

/// Removes the 3 app install limit by patching installd
void grant_full_disk_access(void (^_Nonnull completion)(NSError* _Nullable error));
bool patch_installd(void);
