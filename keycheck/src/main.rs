//! Reads one case per line on stdin and writes one verdict per line, for the
//! differential harness (broker/keydiff). A case is
//! {"op": "chain"|"verify"|"authorize"|"spend", "key", "owners", "use", "sig",
//! "step", "task", "amount", "ctx"}; a verdict is {"valid", "bad", "codes",
//! "hold", "scopes"}.

use keycheck::{chain, verify, wire, Context, Step};
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
}

fn verdict(c: &Case) -> serde_json::Value {
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
