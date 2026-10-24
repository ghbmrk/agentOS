//! The wire contract shared with broker/kernel/key: the key's JSON, the byte
//! strings each signature covers and the IDs. This is the only part taken from
//! the Go library rather than from SPEC, since both sides must sign and hash
//! the same bytes. A signed body is the JSON encoding broker/kernel/key gives
//! it, so it is rebuilt here byte for byte (see `GoJson`).

use base64::Engine as _;
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

pub const DOMAIN_ROOT: &str = "agentos.key.root.v1\x00";
pub const DOMAIN_LINK: &str = "agentos.key.link.v1\x00";
pub const DOMAIN_USE: &str = "agentos.key.use.v1\x00";
pub const DOMAIN_ID: &str = "agentos.key.id.v1\x00";

pub type Id = [u8; 32];

/// Bytes travel as standard base64 with padding; null is absent, which is not
/// the same as empty in a signed body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Option<Vec<u8>>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        match s {
            None => Ok(Bytes(None)),
            Some(s) => base64::engine::general_purpose::STANDARD
                .decode(s)
                .map(|b| Bytes(Some(b)))
                .map_err(serde::de::Error::custom),
        }
    }
}

impl Bytes {
    pub fn get(&self) -> &[u8] {
        self.0.as_deref().unwrap_or(&[])
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Root {
    pub owner: Bytes,
    pub clerk: String,
    pub verbs: Option<Vec<String>>,
    pub serial: String,
    pub sig: Bytes,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Link {
    pub caveats: Option<Vec<Caveat>>,
    pub holder: Bytes,
    pub sig: Bytes,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Key {
    pub root: Root,
    pub links: Option<Vec<Link>>,
}

impl Key {
    pub fn links(&self) -> &[Link] {
        self.links.as_deref().unwrap_or(&[])
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Caveat {
    pub kind: String,
    pub set: Option<Vec<String>>,
    pub arg: Option<ArgBound>,
    pub n: i64,
    pub m: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ArgBound {
    pub name: String,
    pub one_of: Option<Vec<String>>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

/// GoJson writes JSON the way Go's encoding/json does for these types: fields
/// in declaration order, no spaces, HTML-safe string escapes, nil as null.
struct GoJson(Vec<u8>);

impl GoJson {
    fn raw(&mut self, s: &str) {
        self.0.extend_from_slice(s.as_bytes());
    }

    fn str(&mut self, s: &str) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.0.push(b'"');
        for c in s.chars() {
            match c {
                '"' => self.raw("\\\""),
                '\\' => self.raw("\\\\"),
                '\n' => self.raw("\\n"),
                '\r' => self.raw("\\r"),
                '\t' => self.raw("\\t"),
                '\u{8}' => self.raw("\\b"),
                '\u{c}' => self.raw("\\f"),
                c if (c as u32) < 0x20 || c == '<' || c == '>' || c == '&' => {
                    let b = c as u32;
                    self.raw("\\u00");
                    self.0.push(HEX[(b >> 4) as usize]);
                    self.0.push(HEX[(b & 0xf) as usize]);
                }
                '\u{2028}' => self.raw("\\u2028"),
                '\u{2029}' => self.raw("\\u2029"),
                c => {
                    let mut buf = [0u8; 4];
                    self.raw(c.encode_utf8(&mut buf));
                }
            }
        }
        self.0.push(b'"');
    }

    fn bytes(&mut self, b: &Bytes) {
        match &b.0 {
            None => self.raw("null"),
            Some(v) => {
                let s = base64::engine::general_purpose::STANDARD.encode(v);
                self.0.push(b'"');
                self.raw(&s);
                self.0.push(b'"');
            }
        }
    }

    fn strs(&mut self, v: &Option<Vec<String>>) {
        match v {
            None => self.raw("null"),
            Some(v) => {
                self.0.push(b'[');
                for (i, s) in v.iter().enumerate() {
                    if i > 0 {
                        self.0.push(b',');
                    }
                    self.str(s);
                }
                self.0.push(b']');
            }
        }
    }

    fn int(&mut self, n: i64) {
        self.raw(&n.to_string());
    }

    fn opt_int(&mut self, n: Option<i64>) {
        match n {
            None => self.raw("null"),
            Some(n) => self.int(n),
        }
    }

    fn caveat(&mut self, c: &Caveat) {
        self.raw("{\"kind\":");
        self.str(&c.kind);
        self.raw(",\"set\":");
        self.strs(&c.set);
        self.raw(",\"arg\":");
        match &c.arg {
            None => self.raw("null"),
            Some(a) => {
                self.raw("{\"name\":");
                self.str(&a.name);
                self.raw(",\"one_of\":");
                self.strs(&a.one_of);
                self.raw(",\"min\":");
                self.opt_int(a.min);
                self.raw(",\"max\":");
                self.opt_int(a.max);
                self.raw("}");
            }
        }
        self.raw(",\"n\":");
        self.int(c.n);
        self.raw(",\"m\":");
        self.int(c.m);
        self.raw("}");
    }
}

pub fn root_body(r: &Root) -> Vec<u8> {
    let mut j = GoJson(Vec::new());
    j.raw("{\"owner\":");
    j.bytes(&r.owner);
    j.raw(",\"clerk\":");
    j.str(&r.clerk);
    j.raw(",\"verbs\":");
    j.strs(&r.verbs);
    j.raw(",\"serial\":");
    j.str(&r.serial);
    j.raw("}");
    j.0
}

pub fn link_body(l: &Link) -> Vec<u8> {
    let mut j = GoJson(Vec::new());
    j.raw("{\"caveats\":");
    match &l.caveats {
        None => j.raw("null"),
        Some(cs) => {
            j.raw("[");
            for (i, c) in cs.iter().enumerate() {
                if i > 0 {
                    j.raw(",");
                }
                j.caveat(c);
            }
            j.raw("]");
        }
    }
    j.raw(",\"holder\":");
    j.bytes(&l.holder);
    j.raw("}");
    j.0
}

fn hash(parts: &[&[u8]]) -> Id {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn root_id(r: &Root) -> Id {
    hash(&[DOMAIN_ID.as_bytes(), &root_body(r), r.sig.get()])
}

pub fn link_id(prev: &Id, l: &Link) -> Id {
    hash(&[DOMAIN_ID.as_bytes(), prev, &link_body(l), l.sig.get()])
}

/// The budget a clerk's first links share under one root (KEY-4: a clerk
/// key's caps are the clerk's one budget under its root).
pub fn account_id(root: &Id, holder: &[u8]) -> Id {
    hash(&[DOMAIN_ID.as_bytes(), b"account\x00", root, holder])
}

pub fn root_msg(r: &Root) -> Vec<u8> {
    [DOMAIN_ROOT.as_bytes(), &root_body(r)].concat()
}

pub fn link_msg(prev: &Id, l: &Link) -> Vec<u8> {
    [DOMAIN_LINK.as_bytes(), prev, &link_body(l)].concat()
}

pub fn use_msg(tip: &Id, use_: &[u8]) -> Vec<u8> {
    [DOMAIN_USE.as_bytes(), tip, use_].concat()
}

pub fn hex(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_as_go_does() {
        let mut j = GoJson(Vec::new());
        j.str("a\"\\<>&\u{1}\n\u{2028}é");
        assert_eq!(
            String::from_utf8(j.0).unwrap(),
            "\"a\\\"\\\\\\u003c\\u003e\\u0026\\u0001\\n\\u2028é\""
        );
    }

    #[test]
    fn null_and_empty_differ() {
        let a = Link {
            caveats: None,
            holder: Bytes(None),
            sig: Bytes(None),
        };
        let b = Link {
            caveats: Some(vec![]),
            holder: Bytes(Some(vec![])),
            sig: Bytes(None),
        };
        assert_eq!(link_body(&a), b"{\"caveats\":null,\"holder\":null}");
        assert_eq!(link_body(&b), b"{\"caveats\":[],\"holder\":\"\"}");
    }
}
