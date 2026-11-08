//! Where `pam-passkey` and `pam_passkey.so` may live (DR-0003 置き場). The PAM module checks
//! the helper before spawning it, and `setup` checks the same way before writing settings.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The file and every directory up to `/` must be root-owned, not writable by group or
/// others, and not symlinks.
pub fn secure_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = Some(path);
    while let Some(part) = current {
        let Ok(metadata) = part.symlink_metadata() else {
            return false;
        };
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return false;
        }
        if part == path && !metadata.is_file() || part != path && !metadata.is_dir() {
            return false;
        }
        current = part.parent();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // A path is trusted only if every component, including / and the file, is root-owned and
    // non-writable by others; relative paths cannot be checked and are refused.
    #[test]
    fn rejects_relative_and_user_owned_paths() {
        assert!(!secure_path(Path::new("target/release/pam-passkey")));
        // The test binary lives in a user-owned build directory.
        assert!(!secure_path(&std::env::current_exe().unwrap()));
        assert!(secure_path(Path::new("/bin/sh")));
        // A root-owned symlink is still refused (/tmp -> private/tmp).
        assert!(!secure_path(Path::new("/tmp")));
        // A directory is not an executable.
        assert!(!secure_path(Path::new("/bin")));
    }
}
