//! Kernel-provided peer identity for Unix domain socket connections.

use std::path::{Path, PathBuf};

/// Absolute executable path of `pid` via `proc_pidpath(2)`.
#[must_use]
pub fn executable_path(pid: i32) -> Option<PathBuf> {
    let mut buf = vec![0u8; 4 * libc::PATH_MAX as usize];
    // SAFETY: proc_pidpath writes at most `buf.len()` bytes into `buf`.
    let n = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(usize::try_from(n).ok()?);
    if let Some(nul) = buf.iter().position(|&b| b == 0) {
        buf.truncate(nul);
    }
    String::from_utf8(buf).ok().map(PathBuf::from)
}

/// Human readable app name from an executable path inside an `.app` bundle.
#[must_use]
pub fn app_name(exe: &Path) -> Option<String> {
    exe.ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .map(str::to_owned)
}

#[must_use]
pub fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_executable_resolves() {
        let p = executable_path(i32::try_from(std::process::id()).unwrap()).unwrap();
        assert!(p.is_absolute());
    }

    #[test]
    fn app_name_from_bundle() {
        assert_eq!(
            app_name(Path::new(
                "/Applications/Google Chrome.app/Contents/Frameworks/x/Helpers/chrome_helper"
            ))
            .as_deref(),
            Some("Google Chrome")
        );
        assert_eq!(app_name(Path::new("/usr/bin/ssh")), None);
    }
}
