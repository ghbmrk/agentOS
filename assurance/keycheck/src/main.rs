//! Reads one case per line on stdin and writes one verdict per line, for the
//! differential harness (broker/test/keydiff). A case is
//! {"op": "chain"|"verify"|"authorize"|"spend", "key", "owners", "use", "sig",
//! "step", "task", "amount", "ctx"}; a verdict is {"valid", "bad", "codes",
//! "hold", "scopes", "by_owner", "narrowers"}. A case {"op": "within", "renew",
//! "was"} compares two first links' caveats; its verdict is {"valid",
//! "within"}, valid when both fold.

use keycheck::{chain, fold, verify, wire, within, Context, Step};
use serde::Deserialize;
use std::io::{self, BufRead, Write};

#[derive(Deserialize, Default)]
#[serde(default)]
struct Case {
    op: String,
    key: wire::Key,
    owners: Vec<wire::Bytes>,
    #[serde(rename = "use")]
    use_: wire::Bytes,
    sig: wire::Bytes,
    step: Step,
    task: String,
    amount: i64,
    ctx: Context,
    renew: Option<Vec<wire::Caveat>>,
    was: Option<Vec<wire::Caveat>>,
}

fn verdict(c: &Case) -> serde_json::Value {
    if c.op == "within" {
        return match (
            fold(c.renew.as_deref().unwrap_or(&[])),
            fold(c.was.as_deref().unwrap_or(&[])),
        ) {
            (Ok(n), Ok(o)) => serde_json::json!({"valid": true, "within": within(&n, &o)}),
            (Err(b), _) | (_, Err(b)) => {
                serde_json::json!({"valid": false, "bad": format!("{b:?}")})
            }
        };
    }
    let owners: Vec<Vec<u8>> = c.owners.iter().map(|b| b.get().to_vec()).collect();
    let checked = match c.op.as_str() {
        "chain" | "spend" => chain(&c.key, &owners),
        _ => verify(&c.key, &owners, c.use_.get(), c.sig.get()),
    };
    let k = match checked {
        Err(b) => return serde_json::json!({"valid": false, "bad": format!("{b:?}")}),
        Ok(k) => k,
    };
    let codes: Vec<&str> = match c.op.as_str() {
        "authorize" => k.authorize(&c.step, &c.ctx).into_iter().collect(),
        "spend" => k.spend(&c.task, c.amount, &c.ctx).into_iter().collect(),
        _ => vec![],
    };
    serde_json::json!({
        "valid": true,
        "codes": codes,
        "hold": [k.limits.window(false), k.limits.window(true)],
        "scopes": k.scopes().iter().map(wire::hex).collect::<Vec<_>>(),
        "by_owner": k.by_owner,
        "narrowers": k.narrowers.iter().map(|p| p.iter().map(|b| format!("{b:02x}")).collect::<String>()).collect::<Vec<_>>(),
    })
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let v = match serde_json::from_str::<Case>(&line) {
            Ok(c) => verdict(&c),
            Err(e) => serde_json::json!({"valid": false, "bad": format!("decode: {e}")}),
        };
        writeln!(out, "{v}").expect("stdout");
        out.flush().expect("stdout");
    }
}
