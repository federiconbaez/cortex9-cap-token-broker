//! Revocation repositories: in-memory and append-only file.
//!
//! File format, one entry per line: `R <fingerprint-hex> <expires|->\n`.
//! A final line without `\n` is a torn write and is ignored; any other
//! malformed line is an error (fail closed, never "not revoked").

use crate::domain::Fingerprint;
use crate::ports::RevocationStore;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct MemoryRevocations {
    entries: BTreeMap<Fingerprint, Option<u64>>,
}

impl MemoryRevocations {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn merge(entries: &mut BTreeMap<Fingerprint, Option<u64>>, fp: Fingerprint, exp: Option<u64>) {
    // Keep the longest-lived entry: `None` (forever) dominates.
    let e = entries.entry(fp).or_insert(exp);
    *e = match (*e, exp) {
        (None, _) | (_, None) => None,
        (Some(a), Some(b)) => Some(a.max(b)),
    };
}

fn purge(entries: &mut BTreeMap<Fingerprint, Option<u64>>, now: u64) -> usize {
    let before = entries.len();
    entries.retain(|_, exp| exp.map_or(true, |t| t > now));
    before - entries.len()
}

impl RevocationStore for MemoryRevocations {
    type Error = Infallible;

    fn revoke(&mut self, fp: Fingerprint, expires_at: Option<u64>) -> Result<(), Infallible> {
        merge(&mut self.entries, fp, expires_at);
        Ok(())
    }
    fn is_revoked_any(&self, fps: &[Fingerprint]) -> Result<bool, Infallible> {
        Ok(fps.iter().any(|f| self.entries.contains_key(f)))
    }
    fn purge_expired(&mut self, now: u64) -> Result<usize, Infallible> {
        Ok(purge(&mut self.entries, now))
    }
}

#[derive(Debug)]
pub enum FileRevocationError {
    Io(io::Error),
    Corrupt { line: usize },
}

impl fmt::Display for FileRevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileRevocationError::Io(e) => write!(f, "io: {e}"),
            FileRevocationError::Corrupt { line } => {
                write!(f, "corrupt revocation file at line {line}")
            }
        }
    }
}
impl std::error::Error for FileRevocationError {}
impl From<io::Error> for FileRevocationError {
    fn from(e: io::Error) -> Self {
        FileRevocationError::Io(e)
    }
}

pub struct FileRevocations {
    path: PathBuf,
    entries: BTreeMap<Fingerprint, Option<u64>>,
}

impl FileRevocations {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FileRevocationError> {
        let path = path.as_ref().to_path_buf();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e.into()),
        };
        let mut entries = BTreeMap::new();
        let complete = match text.rfind('\n') {
            Some(i) => &text[..=i],
            None => "",
        };
        for (n, line) in complete.lines().enumerate() {
            let corrupt = || FileRevocationError::Corrupt { line: n + 1 };
            let mut parts = line.split(' ');
            if parts.next() != Some("R") {
                return Err(corrupt());
            }
            let fp =
                Fingerprint::from_hex(parts.next().ok_or_else(corrupt)?).map_err(|_| corrupt())?;
            let exp = match parts.next().ok_or_else(corrupt)? {
                "-" => None,
                t => Some(t.parse::<u64>().map_err(|_| corrupt())?),
            };
            if parts.next().is_some() {
                return Err(corrupt());
            }
            merge(&mut entries, fp, exp);
        }
        let mut me = Self { path, entries };
        if complete.len() != text.len() {
            me.rewrite()?; // drop the torn tail durably
        }
        Ok(me)
    }

    fn line(fp: &Fingerprint, exp: Option<u64>) -> String {
        match exp {
            Some(t) => format!("R {} {t}\n", fp.to_hex()),
            None => format!("R {} -\n", fp.to_hex()),
        }
    }

    fn rewrite(&mut self) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            for (fp, exp) in &self.entries {
                f.write_all(Self::line(fp, *exp).as_bytes())?;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

impl RevocationStore for FileRevocations {
    type Error = FileRevocationError;

    fn revoke(
        &mut self,
        fp: Fingerprint,
        expires_at: Option<u64>,
    ) -> Result<(), FileRevocationError> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(Self::line(&fp, expires_at).as_bytes())?;
        f.sync_data()?;
        merge(&mut self.entries, fp, expires_at);
        Ok(())
    }

    fn is_revoked_any(&self, fps: &[Fingerprint]) -> Result<bool, FileRevocationError> {
        Ok(fps.iter().any(|f| self.entries.contains_key(f)))
    }

    fn purge_expired(&mut self, now: u64) -> Result<usize, FileRevocationError> {
        let n = purge(&mut self.entries, now);
        if n > 0 {
            self.rewrite()?;
        }
        Ok(n)
    }
}
