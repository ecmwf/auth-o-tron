// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Bounded reads of operator-provided secret files, such as mounted Kubernetes Secrets.

use std::path::Path;
use zeroize::Zeroizing;

/// Trimmed text of a regular file of at most `limit` bytes: non-empty UTF-8 without
/// control characters. Symlinks are followed (projected Secrets use them); a FIFO or
/// directory is refused without blocking. Valid: `"s3cret\n"` gives `s3cret`.
/// Invalid: an empty file, `"a\u{7}b"`, invalid UTF-8, or more than `limit` bytes.
#[cfg(unix)]
pub fn read_secret_text(path: &Path, limit: usize) -> Option<Zeroizing<String>> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > limit {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    (!text.is_empty() && !text.chars().any(char::is_control))
        .then(|| Zeroizing::new(text.to_owned()))
}

#[cfg(not(unix))]
pub fn read_secret_text(_: &Path, _: usize) -> Option<Zeroizing<String>> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn only_small_plain_text_files_are_read() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "  s3cret  ").unwrap();
        assert_eq!(
            read_secret_text(file.path(), 16).unwrap().as_str(),
            "s3cret"
        );
        assert!(read_secret_text(file.path(), 8).is_none());
        for content in [&b""[..], b" \n", b"a\x07b", b"\xff\xfe"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(content).unwrap();
            assert!(read_secret_text(file.path(), 16).is_none());
        }
        let directory = tempfile::tempdir().unwrap();
        assert!(read_secret_text(directory.path(), 16).is_none());
        let fifo = directory.path().join("fifo");
        let created = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(created.success());
        assert!(read_secret_text(&fifo, 16).is_none());
        assert!(read_secret_text(Path::new("/nonexistent-authotron-test/secret"), 16).is_none());
    }
}
