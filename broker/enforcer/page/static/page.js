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

document.addEventListener("DOMContentLoaded", () => {
  const a = document.getElementById("approve");
  if (a) a.addEventListener("click", async () => {
    a.disabled = true;
    try {
      const r = await post("/approve", { id: a.dataset.id, ...(await tap(a.dataset.challenge, a.dataset.rp)) });
      say(r.applied ? "Applied." : "Approved. It applies at " + r.due + " unless you cancel it on the home page.");
    } catch (e) { say("Not approved: " + e.message); }
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
