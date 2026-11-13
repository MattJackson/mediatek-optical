//! Golden characterization oracle: freezes the library's observable behaviour
//! over a firmware corpus as a deterministic, sorted JSON-lines manifest of
//! SHA-256 digests and identity fields (never raw firmware bytes).
//!
//! Inputs are files or directories (recursively): `.bin` images and MediaTek
//! release-package `.tar`s (each member image is analyzed).
//!
//! `cargo run --release --all-features --example oracle -- <inputs...> > out.jsonl`
//!
//! Every API refactor must reproduce the committed `oracle/golden-library-v1.jsonl`
//! byte-for-byte.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "oracle/api.rs"]
mod api;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// SHA-256 of a value's `Debug` rendering: structural equality of an analysis
/// result without storing it.
fn dbg_sha<T: Debug + ?Sized>(value: &T) -> String {
    sha(format!("{value:?}").as_bytes())
}

/// Members of a ustar archive (regular files only).
fn untar(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= bytes.len() {
        let header = &bytes[at..at + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
        let size_field = String::from_utf8_lossy(&header[124..136]);
        let size =
            usize::from_str_radix(size_field.trim_matches(|c: char| c == '\0' || c == ' '), 8)
                .unwrap_or(0);
        let start = at + 512;
        let end = (start + size).min(bytes.len());
        if header[156] == b'0' || header[156] == 0 {
            out.push((name, bytes[start..end].to_vec()));
        }
        at = start + size.div_ceil(512) * 512;
    }
    out
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for e in entries {
            collect(&e, out);
        }
    } else if path.extension().is_some_and(|e| e == "bin" || e == "tar") {
        out.push(path.to_path_buf());
    }
}

fn main() {
    let mut files = Vec::new();
    for arg in std::env::args().skip(1) {
        collect(Path::new(&arg), &mut files);
    }
    // Each distinct image once, keyed by its digest; record where it came from.
    let mut images: BTreeMap<String, (Vec<u8>, Vec<String>)> = BTreeMap::new();
    let mut packages: BTreeMap<String, Value> = BTreeMap::new();
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        let label = file.file_name().unwrap().to_string_lossy().into_owned();
        if file.extension().is_some_and(|e| e == "tar") {
            let members = untar(&bytes);
            packages.insert(
                sha(&bytes),
                json!({
                    "members": members.iter().map(|(n, d)| json!([n, sha(d)])).collect::<Vec<_>>(),
                }),
            );
            for (name, data) in members {
                if name.ends_with(".bin") {
                    images
                        .entry(sha(&data))
                        .or_insert_with(|| (data.clone(), Vec::new()))
                        .1
                        .push(format!("{}:{name}", sha(&bytes)));
                }
            }
        } else {
            images
                .entry(sha(&bytes))
                .or_insert_with(|| (bytes.clone(), Vec::new()))
                .1
                .push(label);
        }
    }

    let header = json!({
        "format": "mediatek-optical-library-oracle",
        "version": 1,
        "packages": packages.len(),
        "images": images.len(),
    });
    println!("{header}");
    for (id, package) in &packages {
        println!("{}", json!({ "package": id, "detail": package }));
    }
    for (id, (image, mut sources)) in images {
        sources.sort();
        sources.dedup();
        let mut row = api::image(&image);
        row["sha256"] = json!(id);
        row["sources"] = json!(sources);
        println!("{row}");
    }
}

pub(crate) use {dbg_sha as debug_sha, sha as digest};
