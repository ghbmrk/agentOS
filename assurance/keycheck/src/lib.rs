//! keycheck: a second key check, in another language, written from SPEC
//! KEY-1..KEY-8 and the design record (broker/kernel/ASSUMPTIONS.md), so a
//! fault in broker/kernel/key's code or crypto is not shared by this one (SPEC
//! §19 risk 32). It is not a clean-room one: the wire contract (`wire`), the
//! closed tables below and the rules SPEC leaves open are shared with the
//! library, as ASSUMPTIONS.md KD-a lists.
//!
//! The library returns the first refusal it finds; this check returns every
//! refusal a use earns, so the two can be compared without sharing an order.

pub mod wire;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use wire::{Id, Key};

/// A chain holds at most this many links, so a check is bounded.
pub const MAX_LINKS: usize = 32;
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// The closed verb list (VRB-2) with each verb's fixed arguments, the first
/// being the object the step acts on (ASSUMPTIONS MIG-2-t).
pub const VERBS: &[(&str, &[&str])] = &[
    ("read", &["query"]),
    ("fetch", &["url"]),
    ("draft", &["to", "msg"]),
    ("organize", &["target", "label"]),
    ("trash", &["target"]),
    ("present", &["msg"]),
    ("unsubscribe", &["to"]),
    ("send", &["to", "msg"]),
    ("post", &["to", "msg"]),
    ("actuate", &["target", "value"]),
    ("buy", &["to", "amount", "item"]),
    ("share", &["to", "item"]),
    ("delete-remote", &["target"]),
    ("change-account", &["target", "value"]),
    ("reveal-or-create-secret", &["target"]),
    ("actuate-physical", &["target", "value"]),
];

pub fn verb_args(v: &str) -> Option<&'static [&'static str]> {
    VERBS.iter().find(|(n, _)| *n == v).map(|(_, a)| *a)
}

// Refusal codes.
pub const MALFORMED: &str = "malformed";
pub const STOPPED: &str = "stopped";
pub const REVOKED: &str = "revoked";
pub const PAUSED: &str = "paused";
pub const EXPIRED: &str = "expired";
pub const CLERK: &str = "clerk";
pub const VERB: &str = "verb";
pub const ARG: &str = "arg";
pub const CONTENT: &str = "content";
pub const LABELS: &str = "labels";
pub const SPEND_TASK: &str = "spend-task";
pub const SPEND_DAY: &str = "spend-day";
pub const RATE: &str = "rate";
pub const USES: &str = "uses";
pub const TASK: &str = "task";

/// Why a chain is not a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    WrongOwner,
    BadSig,
    Malformed(&'static str),
    Loosens(&'static str),
    UnknownKind,
    Uncaveated,
    NotHolder,
}

/// A cap one link sets, and the ledger scope it counts: a first link's caps
/// are the clerk's account under the root, a later link's its own prefix.
#[derive(Clone, Debug)]
pub struct Cap {
    pub kind: CapKind,
    pub n: i64,
    pub scope: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapKind {
    SpendTask,
    SpendDay,
    RateDay,
    RateRecipient,
    Uses,
}

#[derive(Clone, Debug, Default)]
pub struct Bound {
    pub one_of: Option<BTreeSet<String>>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

/// The conjunction of a chain (KEY-3): every set the intersection, the expiry
/// the earliest, the hold the longest. Kept apart from the per-link caps so
/// each cap counts its own ledger.
#[derive(Clone, Debug, Default)]
pub struct Limits {
    pub clerk: String,
    pub verbs: BTreeSet<String>,
    pub content: Option<BTreeSet<String>>,
    pub labels: Option<BTreeSet<String>>,
    pub args: HashMap<String, Bound>,
    pub expires: Option<i64>,
    pub hold_base: i64,
    pub hold_novelty: i64,
    pub task: Option<String>,
    // The tightest value of each cap so far, for the narrowing rule.
    pub tightest: HashMap<&'static str, i64>,
    /// Set by `fold` once a verbs caveat narrows the closed list.
    pub verbs_named: bool,
}

#[derive(Clone, Debug)]
pub struct Checked {
    /// The root's ID, then each link's.
    pub ids: Vec<Id>,
    pub account: Option<Id>,
    pub limits: Limits,
    pub caps: Vec<Cap>,
    /// The submitter signed the use as the tip's holder.
    pub held: bool,
    /// The tip is a link after the first that an owner passkey signed for
    /// its parent's holder: the owner narrowed the key (KRN-ownerlink).
    pub by_owner: bool,
    /// The passkeys that signed such links, anywhere in the chain, so a
    /// passkey cut off since can be checked against them.
    pub narrowers: Vec<Vec<u8>>,
}

fn pk(b: &[u8]) -> Option<VerifyingKey> {
    let a: [u8; 32] = b.try_into().ok()?;
    VerifyingKey::from_bytes(&a).ok()
}

/// The cofactorless check of RFC 8032, which is what Go's crypto/ed25519
/// does; dalek's verify_strict would also refuse small-order keys.
fn signed(by: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let (Some(k), Ok(s)) = (pk(by), Signature::from_slice(sig)) else {
        return false;
    };
    k.verify(msg, &s).is_ok()
}

fn any_signed(owners: &[Vec<u8>], msg: &[u8], sig: &[u8]) -> bool {
    who_signed(owners, msg, sig).is_some()
}

/// The first owner passkey, in the order given, whose signature sig is.
fn who_signed<'a>(owners: &'a [Vec<u8>], msg: &[u8], sig: &[u8]) -> Option<&'a Vec<u8>> {
    owners.iter().find(|o| o.len() == 32 && signed(o, msg, sig))
}

fn is_owner(owners: &[Vec<u8>], k: &[u8]) -> bool {
    k.len() == 32 && owners.iter().any(|o| o.as_slice() == k)
}

/// A set travels sorted and without repeats, and never as null.
fn canon(s: &Option<Vec<String>>) -> Result<BTreeSet<String>, Bad> {
    let v = s.as_ref().ok_or(Bad::Malformed("null set"))?;
    let set: BTreeSet<String> = v.iter().cloned().collect();
    if set.len() != v.len() || !v.iter().zip(set.iter()).all(|(a, b)| a == b) {
        return Err(Bad::Malformed("set not sorted and unique"));
    }
    Ok(set)
}

impl Limits {
    fn narrow_set(
        cur: &mut Option<BTreeSet<String>>,
        s: BTreeSet<String>,
        what: &'static str,
    ) -> Result<(), Bad> {
        if let Some(c) = cur {
            if !s.is_subset(c) {
                return Err(Bad::Loosens(what));
            }
        }
        *cur = Some(s);
        Ok(())
    }

    fn cap(&mut self, what: &'static str, n: i64) -> Result<(), Bad> {
        if n < 0 {
            return Err(Bad::Malformed("negative cap"));
        }
        if let Some(&c) = self.tightest.get(what) {
            if n > c {
                return Err(Bad::Loosens(what));
            }
        }
        self.tightest.insert(what, n);
        Ok(())
    }

    /// Adds one caveat, refusing any that removes or loosens a limit (KEY-3).
    fn add(&mut self, c: &wire::Caveat, scope: Id, caps: &mut Vec<Cap>) -> Result<(), Bad> {
        let mut capped = |l: &mut Limits, kind: CapKind, what: &'static str| {
            // m = 1 on a day spend cap counts the clerk's whole account (#2838).
            if c.m != 0 && (c.m != 1 || what != "spend-day") {
                return Err(Bad::Malformed("cap scope"));
            }
            l.cap(what, c.n)?;
            caps.push(Cap {
                kind,
                n: c.n,
                scope,
            });
            Ok(())
        };
        match c.kind.as_str() {
            "verbs" => {
                let s = canon(&c.set)?;
                if !s.is_subset(&self.verbs) {
                    return Err(Bad::Loosens("verbs"));
                }
                self.verbs = s;
            }
            "content" => Self::narrow_set(&mut self.content, canon(&c.set)?, "content")?,
            "labels" => Self::narrow_set(&mut self.labels, canon(&c.set)?, "labels")?,
            "arg" => {
                let a = c
                    .arg
                    .as_ref()
                    .ok_or(Bad::Malformed("arg caveat without a bound"))?;
                if a.name.is_empty() {
                    return Err(Bad::Malformed("arg bound names no argument"));
                }
                let one_of = match &a.one_of {
                    None => None,
                    some => Some(canon(some)?),
                };
                if a.min.zip(a.max).is_some_and(|(lo, hi)| lo > hi) {
                    return Err(Bad::Malformed("arg min above max"));
                }
                let b = self.args.entry(a.name.clone()).or_default();
                if let Some(cur) = &b.one_of {
                    match &one_of {
                        Some(s) if s.is_subset(cur) => {}
                        _ => return Err(Bad::Loosens("arg one_of")),
                    }
                }
                if let Some(cur) = b.min {
                    if a.min.is_none_or(|m| m < cur) {
                        return Err(Bad::Loosens("arg min"));
                    }
                }
                if let Some(cur) = b.max {
                    if a.max.is_none_or(|m| m > cur) {
                        return Err(Bad::Loosens("arg max"));
                    }
                }
                *b = Bound {
                    one_of,
                    min: a.min,
                    max: a.max,
                };
            }
            "spend-task" => capped(self, CapKind::SpendTask, "spend-task")?,
            "spend-day" => capped(self, CapKind::SpendDay, "spend-day")?,
            "rate-day" => capped(self, CapKind::RateDay, "rate-day")?,
            "rate-recipient-day" => capped(self, CapKind::RateRecipient, "rate-recipient-day")?,
            "uses" => capped(self, CapKind::Uses, "uses")?,
            "expires" => {
                if self.expires.is_some_and(|e| c.n > e) {
                    return Err(Bad::Loosens("expires"));
                }
                self.expires = Some(c.n);
            }
            "hold" => {
                // The novelty window is the longer one (KEY-8).
                if c.n < 0 || c.m < c.n {
                    return Err(Bad::Malformed("hold windows"));
                }
                if c.n < self.hold_base || c.m < self.hold_novelty {
                    return Err(Bad::Loosens("hold"));
                }
                self.hold_base = c.n;
                self.hold_novelty = c.m;
            }
            "task" => {
                // A key serves one task and moves to no other (KRN-5).
                let s = canon(&c.set)?;
                if s.len() != 1 || s.iter().next().is_some_and(|t| t.is_empty()) {
                    return Err(Bad::Malformed("task caveat names one task"));
                }
                let t = s.into_iter().next();
                if self.task.is_some() && self.task != t {
                    return Err(Bad::Loosens("task"));
                }
                self.task = t;
            }
            _ => return Err(Bad::UnknownKind),
        }
        Ok(())
    }

    /// The hold window an irreversible step waits (KEY-8): the base window
    /// for a familiar shape, the novelty window for a new one.
    pub fn window(&self, novel: bool) -> i64 {
        if novel {
            self.hold_novelty
        } else {
            self.hold_base
        }
    }
}

/// Checks a key as data: the root signed by an owner passkey, every link
/// signed by the holder before it and only narrowing, and every first link
/// bounded by an expiry and a daily spend cap (KEY-1, KEY-3, KEY-4).
pub fn chain(k: &Key, owners: &[Vec<u8>]) -> Result<Checked, Bad> {
    let r = &k.root;
    if !is_owner(owners, r.owner.get()) {
        return Err(Bad::WrongOwner);
    }
    if !signed(r.owner.get(), &wire::root_msg(r), r.sig.get()) {
        return Err(Bad::BadSig);
    }
    // KEY-1: a root names one clerk and a set of verbs from the closed list.
    if r.clerk.is_empty() {
        return Err(Bad::Malformed("root names no clerk"));
    }
    let verbs = canon(&r.verbs)?;
    if verbs.is_empty() || verbs.iter().any(|v| verb_args(v).is_none()) {
        return Err(Bad::Malformed("root verbs"));
    }
    let links = k.links();
    if links.len() > MAX_LINKS {
        return Err(Bad::Malformed("too many links"));
    }
    let mut ids = vec![wire::root_id(r)];
    let mut l = Limits {
        clerk: r.clerk.clone(),
        verbs,
        ..Default::default()
    };
    let mut caps = Vec::new();
    let mut account = None;
    let mut prev_holder: Option<&[u8]> = None;
    let mut by_owner = false;
    let mut narrowers = Vec::new();
    for (i, link) in links.iter().enumerate() {
        let prev = *ids.last().unwrap();
        let holder = link.holder.get();
        // A holder is a 32-byte public key. One that is not a curve point
        // can sign nothing, so a key handed to it is dead, not malformed.
        if holder.len() != 32 {
            return Err(Bad::Malformed("holder is not 32 bytes"));
        }
        let msg = wire::link_msg(&prev, link);
        by_owner = false;
        match prev_holder {
            // A bare root is held by the owner's passkeys (KEY-4).
            None if any_signed(owners, &msg, link.sig.get()) => {}
            // A link is signed by its parent's holder, or by a passkey that
            // narrows the key for that same holder (KRN-ownerlink).
            Some(p) if signed(p, &msg, link.sig.get()) => {}
            Some(p) if p == holder => match who_signed(owners, &msg, link.sig.get()) {
                Some(o) => {
                    by_owner = true;
                    narrowers.push(o.clone());
                }
                None => return Err(Bad::BadSig),
            },
            _ => return Err(Bad::BadSig),
        }
        let id = wire::link_id(&prev, link);
        let scope = if i == 0 {
            let a = wire::account_id(&ids[0], holder);
            account = Some(a);
            a
        } else {
            id
        };
        let cavs = link.caveats.as_deref().unwrap_or(&[]);
        for c in cavs {
            let scope = match account {
                Some(a) if c.kind == "spend-day" && c.m == 1 => a,
                _ => scope,
            };
            l.add(c, scope, &mut caps)?;
        }
        if i == 0 {
            let has = |kind: &str| cavs.iter().any(|c| c.kind == kind);
            if !has("expires") || !has("spend-day") {
                return Err(Bad::Uncaveated);
            }
        }
        ids.push(id);
        prev_holder = Some(holder);
    }
    Ok(Checked {
        ids,
        account,
        limits: l,
        caps,
        held: false,
        by_owner,
        narrowers,
    })
}

/// The limits of one link's caveats alone, as a first link sets them, for
/// comparing a renewal with the grant it renews. Verbs start as the whole
/// closed list, and `verbs_named` says whether a caveat narrowed them.
pub fn fold(cavs: &[wire::Caveat]) -> Result<(Limits, Vec<Cap>), Bad> {
    let mut l = Limits {
        verbs: VERBS.iter().map(|(v, _)| v.to_string()).collect(),
        ..Default::default()
    };
    let mut caps = Vec::new();
    for c in cavs {
        l.add(c, Id::default(), &mut caps)?;
        l.verbs_named |= c.kind == "verbs";
    }
    Ok((l, caps))
}

/// Whether a renewal's first link (`new`) allows nothing the grant it renews
/// (`old`) does not, expiry aside: every limit `old` sets, `new` sets at least
/// as tightly (KEY-4: a renewal at the same limits is live at once).
pub fn within(new: &(Limits, Vec<Cap>), old: &(Limits, Vec<Cap>)) -> bool {
    let ((n, ncaps), (o, ocaps)) = (new, old);
    let set = |a: &Option<BTreeSet<String>>, b: &Option<BTreeSet<String>>| match (a, b) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => a.is_subset(b),
    };
    let verbs = !o.verbs_named || (n.verbs_named && n.verbs.is_subset(&o.verbs));
    let args = o.args.iter().all(|(name, ob)| {
        n.args.get(name).is_some_and(|nb| {
            set(&nb.one_of, &ob.one_of)
                && ob.min.is_none_or(|m| nb.min.is_some_and(|x| x >= m))
                && ob.max.is_none_or(|m| nb.max.is_some_and(|x| x <= m))
        })
    });
    let caps = ocaps
        .iter()
        .all(|oc| ncaps.iter().any(|nc| nc.kind == oc.kind && nc.n <= oc.n));
    let task = o.task.is_none() || n.task == o.task;
    verbs
        && set(&n.content, &o.content)
        && set(&n.labels, &o.labels)
        && args
        && caps
        && task
        && n.hold_base >= o.hold_base
        && n.hold_novelty >= o.hold_novelty
}

/// Checks the chain and that sig is the tip holder's over use: only the last
/// holder can use a key (KEY-1).
pub fn verify(k: &Key, owners: &[Vec<u8>], use_: &[u8], sig: &[u8]) -> Result<Checked, Bad> {
    let mut c = chain(k, owners)?;
    let msg = wire::use_msg(c.ids.last().unwrap(), use_);
    let ok = match k.links().last() {
        None => any_signed(owners, &msg, sig),
        Some(l) => signed(l.holder.get(), &msg, sig),
    };
    if !ok {
        return Err(Bad::NotHolder);
    }
    c.held = true;
    Ok(c)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Arg {
    pub value: String,
    pub source: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Step {
    pub verb: String,
    pub clerk: String,
    pub args: Option<HashMap<String, Arg>>,
    pub content: String,
    pub labels: Option<Vec<String>>,
    pub amount: i64,
    pub recipient: String,
    pub task: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Use {
    pub at: i64,
    pub amount: i64,
    pub recipient: String,
    pub task: String,
}

/// What the log says besides the key and the step: the time, revocations,
/// pauses, STOP, and the uses charged to each chain prefix (hex ID).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Context {
    pub now: i64,
    #[serde(deserialize_with = "nullable")]
    pub revoked: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub paused: Vec<String>,
    pub stopped: bool,
    #[serde(deserialize_with = "nullable")]
    pub uses: HashMap<String, Vec<Use>>,
    /// No revocation view was given: every use fails closed.
    pub no_view: bool,
    /// No ledger was given: a capped key fails closed.
    pub no_ledger: bool,
}

/// Reads null as empty, as a Go nil slice or map is.
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

impl Context {
    fn uses(&self, scope: &Id) -> &[Use] {
        self.uses
            .get(&wire::hex(scope))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

impl Checked {
    /// Every scope a use of this key is charged to: each prefix and, below
    /// the root, the clerk's account.
    pub fn scopes(&self) -> Vec<Id> {
        let mut s = self.ids.clone();
        s.extend(self.account);
        s
    }

    /// Refusals any use shares: STOP, a revoked or paused prefix (KEY-6,
    /// KEY-7), and expiry.
    pub fn live(&self, c: &Context) -> BTreeSet<&'static str> {
        let mut out = BTreeSet::new();
        if c.no_view {
            out.insert(MALFORMED);
        }
        if c.stopped {
            out.insert(STOPPED);
        }
        let hit = |list: &[String]| self.ids.iter().any(|id| list.contains(&wire::hex(id)));
        if hit(&c.revoked) {
            out.insert(REVOKED);
        }
        if hit(&c.paused) {
            out.insert(PAUSED);
        }
        if self.limits.expires.is_some_and(|e| c.now >= e) {
            out.insert(EXPIRED);
        }
        out
    }

    fn task(&self, t: &str, out: &mut BTreeSet<&'static str>) {
        if self.limits.task.as_deref().is_some_and(|k| k != t) {
            out.insert(TASK);
        }
    }

    /// The uses in the rolling day that ends at the context's time.
    fn today<'a>(c: &'a Context, uses: &'a [Use]) -> impl Iterator<Item = &'a Use> + 'a {
        let from = c.now.saturating_sub(DAY_MS);
        uses.iter().filter(move |u| u.at > from)
    }

    /// LOG-7's money caps: the per-task total and the rolling daily total,
    /// each with this charge added, in exact arithmetic so no total wraps.
    fn money(&self, task: &str, amount: i64, c: &Context, out: &mut BTreeSet<&'static str>) {
        if c.no_ledger && !self.caps.is_empty() {
            out.insert(MALFORMED);
        }
        let total = |it: &mut dyn Iterator<Item = &Use>| {
            it.map(|u| u.amount as i128).sum::<i128>() + amount as i128
        };
        for cap in &self.caps {
            let uses = c.uses(&cap.scope);
            let (spent, code) = match cap.kind {
                CapKind::SpendTask => (
                    total(&mut uses.iter().filter(|u| u.task == task)),
                    SPEND_TASK,
                ),
                CapKind::SpendDay => (total(&mut Self::today(c, uses)), SPEND_DAY),
                _ => continue,
            };
            if spent > cap.n as i128 {
                out.insert(code);
            }
        }
    }

    /// KEY-2's counted caps on steps: a rolling daily count, a rolling daily
    /// count per recipient and a lifetime use count, this step included.
    fn counts(&self, s: &Step, c: &Context, out: &mut BTreeSet<&'static str>) {
        for cap in &self.caps {
            let uses = c.uses(&cap.scope);
            let (n, code) = match cap.kind {
                CapKind::RateDay => (Self::today(c, uses).count(), RATE),
                CapKind::RateRecipient => (
                    Self::today(c, uses)
                        .filter(|u| u.recipient == s.recipient)
                        .count(),
                    RATE,
                ),
                CapKind::Uses => (uses.len(), USES),
                _ => continue,
            };
            if n as i128 + 1 > cap.n as i128 {
                out.insert(code);
            }
        }
    }

    /// Every refusal a step earns under this key; empty admits it (KEY-2).
    pub fn authorize(&self, s: &Step, c: &Context) -> BTreeSet<&'static str> {
        let mut out = self.live(c);
        if !self.held {
            out.insert(MALFORMED);
        }
        let l = &self.limits;
        if s.clerk != l.clerk {
            out.insert(CLERK);
        }
        self.task(&s.task, &mut out);
        if !l.verbs.contains(&s.verb) {
            out.insert(VERB);
        }
        let none = HashMap::new();
        let args = s.args.as_ref().unwrap_or(&none);
        let declared = verb_args(&s.verb).unwrap_or(&[]);
        if args.len() != declared.len()
            || declared
                .iter()
                .any(|n| args.get(*n).is_none_or(|a| a.value.is_empty()))
        {
            out.insert(ARG);
        }
        for (name, b) in &l.args {
            // A bounded argument counts only when the owner fixed it or the
            // clerk read it, never when a planner supplied it (KEY-2).
            let Some(a) = args.get(name) else {
                out.insert(ARG);
                continue;
            };
            if a.source != "owner" && a.source != "clerk" {
                out.insert(ARG);
            }
            if b.one_of.as_ref().is_some_and(|set| !set.contains(&a.value)) {
                out.insert(ARG);
            }
            if b.min.is_some() || b.max.is_some() {
                match a.value.parse::<i64>() {
                    Ok(v) if b.min.is_none_or(|m| v >= m) && b.max.is_none_or(|m| v <= m) => {}
                    _ => {
                        out.insert(ARG);
                    }
                }
            }
        }
        if l.content
            .as_ref()
            .is_some_and(|set| !set.contains(&s.content))
        {
            out.insert(CONTENT);
        }
        if let Some(set) = &l.labels {
            if s.labels.iter().flatten().any(|x| !set.contains(x)) {
                out.insert(LABELS);
            }
        }
        if s.amount < 0 {
            out.insert(MALFORMED);
        } else {
            self.money(&s.task, s.amount, c, &mut out);
            self.counts(s, c, &mut out);
        }
        out
    }

    /// Every refusal a metered call (a model or paid API call) of amount
    /// under task earns. LOG-7 meters it against the key's money caps; a key
    /// that sets no money cap has no budget to meter against, so it pays for
    /// no call.
    pub fn spend(&self, task: &str, amount: i64, c: &Context) -> BTreeSet<&'static str> {
        let mut out = self.live(c);
        self.task(task, &mut out);
        if amount < 0 {
            out.insert(MALFORMED);
            return out;
        }
        if !self
            .caps
            .iter()
            .any(|k| matches!(k.kind, CapKind::SpendTask | CapKind::SpendDay))
        {
            out.insert(MALFORMED);
        }
        self.money(task, amount, c, &mut out);
        out
    }
}

// REQ: KEY-1, KEY-2, KEY-3, KEY-4, KEY-7, KEY-8, KRN-5
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use wire::{Bytes, Caveat, Link, Root};

    fn party(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[i; 32])
    }

    fn pub_(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_bytes().to_vec()
    }

    fn cav(kind: &str, n: i64, m: i64, set: Option<&[&str]>) -> Caveat {
        Caveat {
            kind: kind.into(),
            set: set.map(|s| s.iter().map(|x| x.to_string()).collect()),
            arg: None,
            n,
            m,
        }
    }

    fn root(owner: &SigningKey) -> Key {
        let mut r = Root {
            owner: Bytes(Some(pub_(owner))),
            clerk: "mail".into(),
            verbs: Some(vec!["send".into(), "trash".into()]),
            serial: "1".into(),
            sig: Bytes(None),
        };
        r.sig = Bytes(Some(owner.sign(&wire::root_msg(&r)).to_bytes().to_vec()));
        Key {
            root: r,
            links: Some(vec![]),
        }
    }

    fn extend(k: &Key, signer: &SigningKey, holder: &SigningKey, cavs: Vec<Caveat>) -> Key {
        let tip = *chain_ids(k).last().unwrap();
        let mut l = Link {
            caveats: Some(cavs),
            holder: Bytes(Some(pub_(holder))),
            sig: Bytes(None),
        };
        l.sig = Bytes(Some(
            signer.sign(&wire::link_msg(&tip, &l)).to_bytes().to_vec(),
        ));
        let mut out = k.clone();
        out.links.get_or_insert_with(Vec::new).push(l);
        out
    }

    fn chain_ids(k: &Key) -> Vec<Id> {
        let mut ids = vec![wire::root_id(&k.root)];
        for l in k.links() {
            let next = wire::link_id(ids.last().unwrap(), l);
            ids.push(next);
        }
        ids
    }

    fn bounds() -> Vec<Caveat> {
        vec![cav("expires", 1000, 0, None), cav("spend-day", 50, 0, None)]
    }

    #[test]
    fn a_first_link_is_signed_by_a_passkey_and_bounded() {
        let (o, c) = (party(1), party(3));
        let owners = vec![pub_(&o)];
        let k = extend(&root(&o), &o, &c, bounds());
        assert!(chain(&k, &owners).is_ok());
        assert_eq!(
            chain(&extend(&root(&o), &c, &c, bounds()), &owners).unwrap_err(),
            Bad::BadSig
        );
        let unbounded = extend(&root(&o), &o, &c, vec![cav("expires", 1000, 0, None)]);
        assert_eq!(chain(&unbounded, &owners).unwrap_err(), Bad::Uncaveated);
        assert_eq!(
            chain(&root(&party(9)), &owners).unwrap_err(),
            Bad::WrongOwner
        );
    }

    #[test]
    fn a_link_only_narrows() {
        let (o, c, g) = (party(1), party(3), party(4));
        let owners = vec![pub_(&o)];
        let k = extend(&root(&o), &o, &c, bounds());
        let wider = extend(&k, &c, &g, vec![cav("spend-day", 51, 0, None)]);
        assert!(matches!(chain(&wider, &owners), Err(Bad::Loosens(_))));
        let later = extend(&k, &c, &g, vec![cav("expires", 1001, 0, None)]);
        assert!(matches!(chain(&later, &owners), Err(Bad::Loosens(_))));
        let verb = extend(&k, &c, &g, vec![cav("verbs", 0, 0, Some(&["buy"]))]);
        assert!(matches!(chain(&verb, &owners), Err(Bad::Loosens(_))));
        let hold = extend(&k, &c, &g, vec![cav("hold", 10, 20, None)]);
        let shorter = extend(&hold, &g, &g, vec![cav("hold", 5, 20, None)]);
        assert!(matches!(chain(&shorter, &owners), Err(Bad::Loosens(_))));
        let v = chain(
            &extend(&hold, &g, &g, vec![cav("hold", 10, 30, None)]),
            &owners,
        )
        .unwrap();
        assert_eq!((v.limits.window(false), v.limits.window(true)), (10, 30));
        let t1 = extend(&k, &c, &g, vec![cav("task", 0, 0, Some(&["t1"]))]);
        let t2 = extend(&t1, &g, &g, vec![cav("task", 0, 0, Some(&["t2"]))]);
        assert!(matches!(chain(&t2, &owners), Err(Bad::Loosens(_))));
    }

    #[test]
    fn an_owner_narrowing_is_reported() {
        let (o, c, g) = (party(1), party(3), party(4));
        let owners = vec![pub_(&o)];
        let k = extend(&root(&o), &o, &c, bounds());
        let narrowed = extend(&k, &o, &c, vec![cav("uses", 3, 0, None)]);
        let v = chain(&narrowed, &owners).unwrap();
        assert!(v.by_owner);
        assert_eq!(v.narrowers, vec![pub_(&o)]);
        let handed = chain(&extend(&narrowed, &c, &g, vec![]), &owners).unwrap();
        assert!(!handed.by_owner);
        assert_eq!(handed.narrowers, vec![pub_(&o)]);
        assert!(!chain(&k, &owners).unwrap().by_owner);
        assert_eq!(
            chain(&extend(&k, &o, &g, vec![]), &owners).unwrap_err(),
            Bad::BadSig
        );
    }

    #[test]
    fn a_renewal_is_within_the_grant_it_renews() {
        let old = fold(&[
            cav("spend-day", 50, 0, None),
            cav("labels", 0, 0, Some(&["a", "b"])),
            cav("hold", 10, 20, None),
        ])
        .unwrap();
        let same = fold(&[
            cav("labels", 0, 0, Some(&["a"])),
            cav("spend-day", 50, 0, None),
            cav("hold", 10, 20, None),
            cav("verbs", 0, 0, Some(&["send"])),
        ])
        .unwrap();
        assert!(within(&same, &old));
        assert!(!within(&old, &same));
        let raised = fold(&[
            cav("spend-day", 51, 0, None),
            cav("labels", 0, 0, Some(&["a"])),
            cav("hold", 10, 20, None),
        ])
        .unwrap();
        assert!(!within(&raised, &old));
        let shorter = fold(&[
            cav("spend-day", 50, 0, None),
            cav("labels", 0, 0, Some(&["a"])),
            cav("hold", 10, 19, None),
        ])
        .unwrap();
        assert!(!within(&shorter, &old));
    }

    #[test]
    fn a_root_names_one_clerk_and_some_verbs() {
        let o = party(1);
        let owners = vec![pub_(&o)];
        let resign = |f: &dyn Fn(&mut Root)| {
            let mut k = root(&o);
            f(&mut k.root);
            k.root.sig = Bytes(Some(o.sign(&wire::root_msg(&k.root)).to_bytes().to_vec()));
            chain(&k, &owners)
        };
        assert!(matches!(
            resign(&|r| r.clerk.clear()),
            Err(Bad::Malformed(_))
        ));
        assert!(matches!(
            resign(&|r| r.verbs = Some(vec![])),
            Err(Bad::Malformed(_))
        ));
        let c = party(3);
        let mut cavs = bounds();
        cavs.push(Caveat {
            kind: "arg".into(),
            arg: Some(Default::default()),
            ..Default::default()
        });
        assert!(matches!(
            chain(&extend(&root(&o), &o, &c, cavs), &owners),
            Err(Bad::Malformed(_))
        ));
    }

    #[test]
    fn a_money_total_never_wraps() {
        let (o, c) = (party(1), party(3));
        let owners = vec![pub_(&o)];
        let v = chain(&extend(&root(&o), &o, &c, bounds()), &owners).unwrap();
        let mut ctx = Context {
            now: 500,
            ..Default::default()
        };
        ctx.uses.insert(
            wire::hex(&v.account.unwrap()),
            vec![Use {
                at: 499,
                amount: 1,
                ..Default::default()
            }],
        );
        assert!(v.spend("t", i64::MAX, &ctx).contains(SPEND_DAY));
    }

    #[test]
    fn only_the_tip_holder_uses_a_key() {
        let (o, c) = (party(1), party(3));
        let owners = vec![pub_(&o)];
        let k = extend(&root(&o), &o, &c, bounds());
        let tip = *chain_ids(&k).last().unwrap();
        let sig = c.sign(&wire::use_msg(&tip, b"plan")).to_bytes();
        assert!(verify(&k, &owners, b"plan", &sig).is_ok());
        assert_eq!(
            verify(&k, &owners, b"other", &sig).unwrap_err(),
            Bad::NotHolder
        );
        let stripped = Key {
            root: k.root.clone(),
            links: Some(vec![]),
        };
        assert_eq!(
            verify(&stripped, &owners, b"plan", &sig).unwrap_err(),
            Bad::NotHolder
        );
    }

    #[test]
    fn a_step_is_checked_against_every_caveat_and_the_log() {
        let (o, c) = (party(1), party(3));
        let owners = vec![pub_(&o)];
        let mut cavs = bounds();
        cavs.push(cav("task", 0, 0, Some(&["t1"])));
        cavs.push(cav("rate-day", 1, 0, None));
        let k = extend(&root(&o), &o, &c, cavs);
        let tip = *chain_ids(&k).last().unwrap();
        let sig = c.sign(&wire::use_msg(&tip, b"p")).to_bytes();
        let v = verify(&k, &owners, b"p", &sig).unwrap();
        let args = HashMap::from([(
            "target".to_string(),
            Arg {
                value: "m1".into(),
                source: "planner".into(),
            },
        )]);
        let s = Step {
            verb: "trash".into(),
            clerk: "mail".into(),
            args: Some(args),
            task: "t1".into(),
            ..Default::default()
        };
        let mut ctx = Context {
            now: 500,
            ..Default::default()
        };
        assert!(v.authorize(&s, &ctx).is_empty());
        assert!(v
            .authorize(
                &Step {
                    task: "t2".into(),
                    ..s.clone()
                },
                &ctx
            )
            .contains(TASK));
        assert!(v
            .authorize(
                &Step {
                    clerk: "bank".into(),
                    ..s.clone()
                },
                &ctx
            )
            .contains(CLERK));
        assert!(v
            .authorize(
                &Step {
                    verb: "buy".into(),
                    ..s.clone()
                },
                &ctx
            )
            .contains(VERB));
        let account = wire::hex(&v.account.unwrap());
        ctx.uses.insert(
            account,
            vec![Use {
                at: 499,
                ..Default::default()
            }],
        );
        assert!(v.authorize(&s, &ctx).contains(RATE));
        ctx.revoked.push(wire::hex(&v.ids[0]));
        ctx.now = 1000;
        let r = v.authorize(&s, &ctx);
        assert!(r.contains(REVOKED) && r.contains(EXPIRED));
        assert!(v.spend("t1", -1, &Context::default()).contains(MALFORMED));
    }
}
