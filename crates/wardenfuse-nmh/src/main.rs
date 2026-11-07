//! WardenFuse Native Messaging Host.
//!
//! Started on demand by Chromium browsers for the `com.8bit.bitwarden` host. It is a minimal
//! relay between the browser (stdio, native-endian u32 length prefixed JSON) and the running
//! WardenFuse.app (Unix domain socket `~/.wardenfuse/browser.sock`, same framing).
//!
//! It holds no secrets and implements no protocol logic. If WardenFuse is not running it tells
//! the extension it is disconnected and exits.

use std::{
    ffi::CStr,
    io::{self, Read, Write},
    os::unix::{io::AsRawFd, net::UnixStream},
    path::PathBuf,
    thread,
};

const MAX_FRAME: usize = 1024 * 1024;

fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(data)?;
    w.flush()
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(
        || {
            // SAFETY: getpwuid returns a pointer to static storage or null.
            unsafe {
                let pw = libc::getpwuid(libc::geteuid());
                if pw.is_null() || (*pw).pw_dir.is_null() {
                    PathBuf::from("/")
                } else {
                    PathBuf::from(CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned())
                }
            }
        },
        PathBuf::from,
    )
}

fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4 * libc::PATH_MAX as usize];
    // SAFETY: proc_pidpath writes at most buf.len() bytes.
    let n =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), u32::try_from(buf.len()).ok()?) };
    if n <= 0 {
        return None;
    }
    buf.truncate(usize::try_from(n).ok()?);
    String::from_utf8(buf).ok()
}

/// Name of the browser that launched us (`Google Chrome`, `Brave Browser`, ...). Cosmetic only.
fn browser_name() -> String {
    // SAFETY: getppid has no preconditions.
    let ppid = unsafe { libc::getppid() };
    pid_path(ppid)
        .and_then(|p| {
            PathBuf::from(p)
                .ancestors()
                .filter(|a| a.extension().is_some_and(|e| e == "app"))
                .last()
                .and_then(|a| a.file_stem().map(|s| s.to_string_lossy().into_owned()))
        })
        .unwrap_or_default()
}

fn escape_json(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn disconnected_and_exit() -> ! {
    let _ = write_frame(&mut io::stdout().lock(), br#"{"command":"disconnected"}"#);
    std::process::exit(1);
}

fn main() {
    // Chrome passes the calling extension origin as the first argument on macOS.
    let origin = std::env::args().nth(1).unwrap_or_default();

    let sock = home().join(".wardenfuse/browser.sock");
    let Ok(stream) = UnixStream::connect(&sock) else {
        disconnected_and_exit();
    };

    // The socket must belong to our own user (defense in depth against a planted socket).
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid fd and out pointers.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    // SAFETY: geteuid has no preconditions.
    if rc != 0 || uid != unsafe { libc::geteuid() } {
        disconnected_and_exit();
    }

    let announcement = format!(
        "{{\"wardenfuse_nmh\":1,\"origin\":\"{}\",\"browser\":\"{}\"}}",
        escape_json(&origin),
        escape_json(&browser_name())
    );
    let Ok(mut to_app) = stream.try_clone() else {
        disconnected_and_exit();
    };
    if write_frame(&mut to_app, announcement.as_bytes()).is_err() {
        disconnected_and_exit();
    }

    // Browser -> app.
    let reader = thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        while let Ok(Some(frame)) = read_frame(&mut stdin) {
            if write_frame(&mut to_app, &frame).is_err() {
                break;
            }
        }
        // Browser closed the port: tell the app and quit.
        let _ = to_app.shutdown(std::net::Shutdown::Both);
        std::process::exit(0);
    });

    // App -> browser.
    let mut from_app = stream;
    let mut stdout = io::stdout().lock();
    while let Ok(Some(frame)) = read_frame(&mut from_app) {
        if write_frame(&mut stdout, &frame).is_err() {
            break;
        }
    }
    let _ = write_frame(&mut stdout, br#"{"command":"disconnected"}"#);
    drop(reader);
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"{\"a\":1}");
        assert!(read_frame(&mut r).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_frames() {
        let len = u32::try_from(MAX_FRAME + 1).unwrap().to_ne_bytes();
        let mut r = &len[..];
        assert!(read_frame(&mut r).is_err());
    }

    #[test]
    fn escapes_json() {
        assert_eq!(escape_json("a\"b\\c\n"), "a\\\"b\\\\c\\u000a");
    }
}
