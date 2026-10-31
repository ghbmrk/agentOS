// The page's only script: asks the phone's passkey for one tap over the
// challenge the enforcer drew, and posts the assertion back to this origin.
"use strict";
const b64u = {
  dec: s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)),
  enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
};
const say = t => { document.getElementById("result").textContent = t; };

async function tap(challenge, rp) {
  const c = await navigator.credentials.get({ publicKey: {
    challenge: b64u.dec(challenge), rpId: rp, userVerification: "required", timeout: 120000 } });
  const r = c.response;
  return { authenticator_data: b64u.enc(r.authenticatorData), client_data_json: b64u.enc(r.clientDataJSON),
    signature: b64u.enc(r.signature) };
}

async function post(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body), credentials: "omit" });
  const j = await res.json();
  if (!res.ok) throw new Error(j.error || res.statusText);
  return j;
}

// enrol makes a passkey on this enforcer's name, then has it sign the
// enforcer's challenge, which shows the enforcer it holds the key.
async function enrol(code, rp) {
  const user = crypto.getRandomValues(new Uint8Array(16));
  const c = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: rp, name: "Home enforcer" },
    user: { id: user, name: "owner", displayName: "Home owner" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" }, timeout: 120000 } });
  if (c.response.getPublicKeyAlgorithm() !== -7) throw new Error("this passkey's kind is not one the enforcer takes");
  const b = await post("/enrol/begin", { code, public_key: b64u.enc(c.response.getPublicKey()) });
  const g = await navigator.credentials.get({ publicKey: {
    challenge: b64u.dec(b.challenge), rpId: b.rp_id, userVerification: "required", timeout: 120000,
    allowCredentials: [{ type: "public-key", id: c.rawId }] } });
  const r = g.response;
  return post("/enrol/finish", { id: b.id, authenticator_data: b64u.enc(r.authenticatorData),
    client_data_json: b64u.enc(r.clientDataJSON), signature: b64u.enc(r.signature) });
}

// drawQR draws a QR code's modules into an SVG element, with the standard
// four-module quiet zone.
function drawQR(svg, q) {
  const n = q.size + 8, ns = svg.namespaceURI; // the SVG namespace, from the element itself
  svg.setAttribute("viewBox", "0 0 " + n + " " + n);
  svg.setAttribute("shape-rendering", "crispEdges");
  for (let y = 0; y < q.size; y++) for (let x = 0; x < q.size; x++) {
    if (q.modules[y * q.size + x] !== "1") continue;
    const r = document.createElementNS(ns, "rect");
    r.setAttribute("x", x + 4); r.setAttribute("y", y + 4); r.setAttribute("width", 1); r.setAttribute("height", 1);
    svg.appendChild(r);
  }
}

function shown(r) {
  for (const f of document.querySelectorAll("form")) f.hidden = true;
  document.getElementById("shown").hidden = false;
  document.getElementById("recovery").textContent = r.recovery;
  if (r.due) document.getElementById("due").textContent =
    "Your new passkey replaces the old one at " + r.due + ". Come back to this page after that to finish.";
  if (r.network) {
    document.getElementById("network").hidden = false;
    document.getElementById("ssid").textContent = r.network.ssid;
    document.getElementById("password").textContent = r.network.password;
    drawQR(document.getElementById("qr"), r.network.qr);
    const pw = r.network.password.replace(/ /g, "");
    document.getElementById("last4").addEventListener("input", e => {
      document.getElementById("joined").hidden = e.target.value.replace(/ /g, "").toUpperCase() !== pw.slice(-4).toUpperCase();
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const ef = document.getElementById("enrol");
  if (ef) ef.addEventListener("submit", async e => {
    e.preventDefault();
    const btn = ef.querySelector("button");
    btn.disabled = true;
    try { shown(await enrol(ef.elements.code.value, ef.dataset.rp)); say(""); }
    catch (err) { say("Not enrolled: " + err.message); btn.disabled = false; }
  });
  const rf = document.getElementById("reset");
  if (rf) rf.addEventListener("submit", async e => {
    e.preventDefault();
    if (!confirm("Reset? Your current passkey and recovery code stop working.")) return;
    try { await post("/enrol/reset", { code: rf.elements.code.value }); location.reload(); }
    catch (err) { say("Not reset: " + err.message); }
  });
  const a = document.getElementById("approve");
  if (a) a.addEventListener("click", async () => {
    a.disabled = true;
    try {
      // A device's sealed secret rides the link's fragment, which the
      // browser never sent; it goes back with the tap (ENF decision 10).
      const sealed = a.dataset.sealed ? { sealed: location.hash.slice(1) } : {};
      const r = await post("/approve", { id: a.dataset.id, ...sealed, ...(await tap(a.dataset.challenge, a.dataset.rp)) });
      say(r.applied ? "Applied." : "Approved. It applies at " + r.due + " unless you cancel it on the home page.");
    } catch (e) { say("Not approved: " + e.message); }
  });
  const d = document.getElementById("do");
  if (d) d.addEventListener("click", async () => {
    d.disabled = true;
    try {
      await post("/do", { id: d.dataset.id, ...(await tap(d.dataset.challenge, d.dataset.rp)) });
      say("Done.");
    } catch (e) { say("Not done: " + e.message); }
  });
  for (const b of document.querySelectorAll("button.act")) b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      const c = await post("/challenge", { action: b.dataset.action, target: b.dataset.target });
      await post("/act", { id: c.id, action: b.dataset.action, ...(await tap(c.challenge, c.rp_id)) });
      say("Done.");
      location.reload();
    } catch (e) { say("Not done: " + e.message); b.disabled = false; }
  });
});
