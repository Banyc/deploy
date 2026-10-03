//! Cryptographic digest helpers (SHA-256).
//!
//! The implementation lives in `storekit::digest` (its prior home was this
//! file, verbatim); this module re-exports it so every `crate::digest::…`
//! call site keeps compiling unchanged. `deploy::digest` is public API, and a
//! glob re-export preserves all of it (`sha256_bytes`, `sha256_reader`,
//! `Hasher`).

pub use storekit::digest::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Byte-identity fixture: the expected digest is what `deploy`'s own
    /// former `digest` implementation produced for this input (and what
    /// `shasum -a 256` prints), so it pins the crate's SHA-256 to deploy's
    /// historical output. The fixture (`bytes(0..=255)` repeated 300 times,
    /// then the ASCII tag `deploy/storekit digest fixture v1`) is 76833 bytes
    /// — larger than the 64 KiB streaming buffer, so `sha256_reader` takes
    /// more than one read.
    #[test]
    fn sha256_fixture_digest_is_stable() {
        const EXPECTED: &str = "d942679f8f33c20fa90e5af131f2819842770e798400024c6cc177e6374c3528";
        let mut fixture = Vec::new();
        for _ in 0..300 {
            fixture.extend(0u8..=255);
        }
        fixture.extend_from_slice(b"deploy/storekit digest fixture v1");
        assert_eq!(fixture.len(), 76833);
        assert_eq!(sha256_bytes(&fixture), EXPECTED);
        assert_eq!(
            sha256_reader(std::io::Cursor::new(&fixture)).unwrap(),
            EXPECTED
        );
    }
}
