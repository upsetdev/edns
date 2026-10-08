//! Self-validating lookup tokens.
//!
//! A token is hex(expiry ‖ nonce ‖ mac), where expiry is a big-endian u32 of
//! unix seconds and mac is HMAC-SHA256(secret, expiry ‖ nonce) truncated. The
//! MAC makes tokens self-validating: forged or expired labels are rejected in
//! memory, so random-subdomain floods never reach the store, and minting
//! needs no store write at all.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::clock::unix_secs;
use crate::config::Config;

const EXPIRY_BYTES: usize = 4;
const NONCE_BYTES: usize = 8;
const MAC_BYTES: usize = 8;
const SIGNED_BYTES: usize = EXPIRY_BYTES + NONCE_BYTES;
const TOKEN_BYTES: usize = SIGNED_BYTES + MAC_BYTES;

/// The number of hex characters in a minted token.
pub const TOKEN_LEN: usize = 2 * TOKEN_BYTES;

/// Returns a fresh token that expires `cfg.ttl` after `now`.
pub fn mint(cfg: &Config, now: SystemTime) -> String {
    let mut b = [0u8; TOKEN_BYTES];
    // Fits until 2106; past that the expiry wraps (and tokens stop verifying).
    let expiry = unix_secs(now + cfg.ttl) as u32;
    b[..EXPIRY_BYTES].copy_from_slice(&expiry.to_be_bytes());
    rand::fill(&mut b[EXPIRY_BYTES..SIGNED_BYTES]);
    let mac = mac(&cfg.token_secret, &b[..SIGNED_BYTES]);
    b[SIGNED_BYTES..].copy_from_slice(&mac);
    hex::encode(b)
}

/// Returns the expiry of `label` if it is a token we minted that has not yet
/// expired at `now`.
pub fn verify(cfg: &Config, label: &str, now: SystemTime) -> Option<SystemTime> {
    // Lower-case only: callers lower-case DNS names and Host headers, and this
    // keeps one canonical spelling (and store key) per token.
    if label.len() != TOKEN_LEN || !label.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut b = [0u8; TOKEN_BYTES];
    hex::decode_to_slice(label, &mut b).ok()?;

    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&cfg.token_secret).ok()?;
    m.update(&b[..SIGNED_BYTES]);
    // Constant-time comparison of the truncated MAC.
    m.verify_truncated_left(&b[SIGNED_BYTES..]).ok()?;

    let expiry = u32::from_be_bytes(b[..EXPIRY_BYTES].try_into().unwrap());
    let expires = UNIX_EPOCH + Duration::from_secs(expiry.into());
    (now < expires).then_some(expires)
}

fn mac(secret: &[u8], msg: &[u8]) -> [u8; MAC_BYTES] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(msg);
    m.finalize().into_bytes()[..MAC_BYTES].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::test_config;
    use std::collections::HashSet;

    #[test]
    fn minted_tokens_verify() {
        let cfg = test_config();
        let now = SystemTime::now();
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let tok = mint(&cfg, now);
            assert_eq!(tok.len(), TOKEN_LEN);
            assert!(tok.len() <= 63, "must fit in one DNS label");
            let expires = verify(&cfg, &tok, now).expect("freshly minted token verifies");
            assert_eq!(unix_secs(expires), unix_secs(now + cfg.ttl));
            assert!(seen.insert(tok), "duplicate token");
        }
    }

    #[test]
    fn rejects() {
        let cfg = test_config();
        let now = SystemTime::now();
        let tok = mint(&cfg, now);

        let mut other = cfg.clone();
        other.token_secret = b"some-other-secret-some-other-secret".to_vec();
        let mut tampered = tok.clone().into_bytes();
        tampered[10] = if tampered[10] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(tampered).unwrap();

        let cases = [
            ("expired", tok.clone(), now + cfg.ttl),
            ("other secret", mint(&other, now), now),
            ("tampered", tampered, now),
            ("upper case", tok.to_uppercase(), now),
            ("too short", tok[1..].to_string(), now),
            ("too long", format!("{tok}0"), now),
            ("empty", String::new(), now),
            ("non-hex", "g".repeat(TOKEN_LEN), now),
            ("old format", "0123456789abcdef".into(), now),
        ];
        for (name, label, at) in cases {
            assert!(verify(&cfg, &label, at).is_none(), "{name}: verify({label:?}) accepted");
        }
    }
}
