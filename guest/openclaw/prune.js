// Deletes from the installed guest packages the files the guest never loads (D-308, #4436).
// The list is the "pruned" entries of assurance/vulncheck.json for this guest's lockfile, the
// same list tools/vulncheck.py reads, so the scan skips exactly what the image no longer holds.
// Any entry that does not match the installed tree fails the build: a wrong version, a missing
// path, a directory that is a file or a file that is a directory, or a path outside the package.
//
// Usage: node prune.js CONFIG WHERE NODE_MODULES_DIR
"use strict";
const fs = require("fs");
const path = require("path");

const [config, where, nodeModules] = process.argv.slice(2);
if (!config || !where || !nodeModules) {
  console.error("usage: node prune.js CONFIG WHERE NODE_MODULES_DIR");
  process.exit(2);
}
const fail = (msg) => {
  console.error(`prune: ${msg}`);
  process.exit(1);
};
const entries = (JSON.parse(fs.readFileSync(config, "utf8")).pruned || []).filter((e) => e.where === where);
for (const e of entries) {
  const at = e.holder.lastIndexOf("@");
  const name = e.holder.slice(0, at), version = e.holder.slice(at + 1);
  const steps = e.path.replace(/\/$/, "").split("/");
  if (at <= 0 || !version || e.path.startsWith("/") || steps.some((s) => ["", ".", "..", "node_modules"].includes(s))) {
    fail(`${e.holder}:${e.path} is not a relative path in a name@version package`);
  }
  const pkg = path.join(nodeModules, name);
  let installed;
  try {
    installed = JSON.parse(fs.readFileSync(path.join(pkg, "package.json"), "utf8")).version;
  } catch (err) {
    fail(`${e.holder}: not installed (${err.message})`);
  }
  if (installed !== version) fail(`${e.holder}: installed version is ${installed}`);
  const target = path.join(pkg, e.path);
  const st = fs.lstatSync(target, { throwIfNoEntry: false });
  const dir = e.path.endsWith("/");
  if (!st || (dir ? !st.isDirectory() : !st.isFile())) {
    fail(`${e.holder}:${e.path} is not an installed ${dir ? "directory" : "file"}; requalify the entry`);
  }
  fs.rmSync(target, { recursive: dir });
  if (fs.existsSync(target)) fail(`${e.holder}:${e.path} is still present`);
  console.log(`pruned ${e.holder}:${e.path}`);
}
