// Deletes from the installed guest packages the files the guest never loads (D-308, #4436).
// The list is the "pruned" entries of assurance/vulncheck.json for this guest's lockfile, the
// same list tools/vulncheck.py reads, so the scan skips exactly what the image no longer holds.
// Each path is deleted under every path the lockfile installs the holder at (its packages keys,
// bundled and linked entries aside), which are exactly the tarballs the scan skips it in. Any
// entry that does not match the installed tree fails the build: a holder the lockfile does not
// install, a wrong version, a missing path, a directory that is a file or a file that is a
// directory, or a name or path with an empty, . or .. step.
//
// Usage: node prune.js CONFIG WHERE INSTALL_DIR   (INSTALL_DIR holds the package-lock.json npm ci installed)
"use strict";
const fs = require("fs");
const path = require("path");

const [config, where, install] = process.argv.slice(2);
if (!config || !where || !install) {
  console.error("usage: node prune.js CONFIG WHERE INSTALL_DIR");
  process.exit(2);
}
const fail = (msg) => {
  console.error(`prune: ${msg}`);
  process.exit(1);
};
// OpenClaw only: a plan CLI guest runs as its provider ships it (CLK-7; vulncheck.py PRUNABLE).
if (where !== "guest/openclaw/package-lock.json") fail(`${where} is not a guest whose build may prune`);
const bad = (p) => p.startsWith("/") || p.replace(/\/$/, "").split("/").some((s) => ["", ".", "..", "node_modules"].includes(s));
const packages = JSON.parse(fs.readFileSync(path.join(install, "package-lock.json"), "utf8")).packages || {};
const entries = (JSON.parse(fs.readFileSync(config, "utf8")).pruned || []).filter((e) => e.where === where);
// Every entry is checked before anything is deleted, so a failed build leaves the tree whole.
const targets = [];
for (const e of entries) {
  const at = e.holder.lastIndexOf("@");
  const name = e.holder.slice(0, at), version = e.holder.slice(at + 1);
  if (at <= 0 || !version || bad(name) || bad(e.path)) {
    fail(`${e.holder}:${e.path} is not a relative path in a name@version package`);
  }
  // The keys lock_tarballs (vulncheck.py) reads: every installed copy with a tarball of its own.
  const keys = Object.keys(packages).filter((k) => {
    const p = packages[k];
    return k && !p.inBundle && !p.link && (p.name || k.split("node_modules/").pop()) === name && p.version === version;
  });
  if (!keys.length) fail(`${e.holder}: the lockfile installs no such package`);
  const dir = e.path.endsWith("/");
  for (const k of keys) {
    const pkg = path.join(install, k);
    let installed;
    try {
      installed = JSON.parse(fs.readFileSync(path.join(pkg, "package.json"), "utf8")).version;
    } catch (err) {
      fail(`${e.holder} at ${k}: not installed (${err.message})`);
    }
    if (installed !== version) fail(`${e.holder} at ${k}: installed version is ${installed}`);
    const target = path.join(pkg, e.path);
    const st = fs.lstatSync(target, { throwIfNoEntry: false });
    if (!st || (dir ? !st.isDirectory() : !st.isFile())) {
      fail(`${e.holder}:${e.path} at ${k} is not an installed ${dir ? "directory" : "file"}; requalify the entry`);
    }
    targets.push({ target, dir, label: `${e.holder}:${e.path} at ${k}` });
  }
}
for (const { target, dir, label } of targets) {
  fs.rmSync(target, { recursive: dir });
  if (fs.existsSync(target)) fail(`${label} is still present`);
  console.log(`pruned ${label}`);
}
