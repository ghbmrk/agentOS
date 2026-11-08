// Runs static/page.js against a stub DOM built from the enrolment screen
// the server rendered (#4929 R-P1), and asserts what the owner is shown.
// An id page.js reads that the screen lacks is null here, as in a browser.
//
//   node pagejs.js page.js factory.html reset.html enrolled.html home.html
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const [script, factoryHTML, resetHTML, enrolledHTML, homeHTML] = process.argv.slice(2).map(p => fs.readFileSync(p, "utf8"));

// dom is a flat stub of html's elements: each tag with an id, a form's
// button and named inputs, its hidden attribute, and the page actions'
// buttons (class "act") by their data-action.
function dom(html) {
  const byId = {}, forms = [], acts = [];
  let form = null;
  for (const m of html.matchAll(/<(\/?)(\w+)([^>]*)>/g)) {
    const [, close, tag, attrs] = m;
    if (close) { if (tag === "form") form = null; continue; }
    const attr = n => { const a = attrs.match(new RegExp("\\b" + n + "=\"([^\"]*)\"")); return a && a[1]; };
    const el = {
      tag, id: attr("id"), hidden: /\shidden\b/.test(attrs), textContent: "", disabled: false, value: "",
      dataset: {}, elements: {}, listeners: {}, children: [], namespaceURI: "svg",
      addEventListener(t, f) { this.listeners[t] = f; },
      setAttribute() {}, appendChild(c) { this.children.push(c); },
      querySelector(s) { return s === "button" ? this.button : null; },
    };
    for (const d of ["rp", "action", "target", "confirm"]) {
      const v = attr("data-" + d);
      if (v !== null) el.dataset[d] = v;
    }
    if (tag === "button" && attr("class") === "act") acts.push(el);
    if (el.id) byId[el.id] = el;
    if (tag === "form") { forms.push(el); form = el; }
    if (form && tag === "button") form.button = el;
    if (form && tag === "input" && attr("name")) form.elements[attr("name")] = el;
  }
  return { byId, forms, acts };
}

// run loads page.js on html with fetch answering answers[path] as
// [status, body], or as a list of them taken in turn, and returns the stub
// elements; confirmed is the owner's answer to a confirm().
function run(html, answers, confirmed = true) {
  const { byId, forms, acts } = dom(html);
  const posted = [];
  let ready = null;
  const cred = { rawId: new ArrayBuffer(1), response: {
    getPublicKeyAlgorithm: () => -7, getPublicKey: () => new ArrayBuffer(1),
    authenticatorData: new ArrayBuffer(1), clientDataJSON: new ArrayBuffer(1), signature: new ArrayBuffer(1) } };
  const ctx = {
    document: {
      getElementById: id => byId[id] || null,
      querySelectorAll: s => s === "form" ? forms : s === "button.act" ? acts : [],
      querySelector: () => ({ content: "token" }),
      addEventListener: (t, f) => { ready = f; },
      createElementNS: () => ({ tag: "rect", setAttribute() {} }),
    },
    navigator: { credentials: { create: async () => cred, get: async () => cred } },
    crypto: { getRandomValues: a => a },
    atob: s => Buffer.from(s, "base64").toString("binary"),
    btoa: s => Buffer.from(s, "binary").toString("base64"),
    fetch: async path => {
      posted.push(path);
      const a = answers[path];
      const [status, body] = Array.isArray(a[0]) ? a.shift() : a;
      return { ok: status === 200, status, statusText: "", json: async () => body };
    },
    confirm: () => confirmed,
    location: { reload() { ctx.reloaded = true; }, hash: "" },
    Uint8Array, ArrayBuffer, Error, String, JSON,
  };
  vm.runInNewContext(script, ctx);
  ready();
  return { el: byId, ctx, acts, posted };
}

const begin = [200, { id: "t", challenge: "AA", rp_id: "enforcer.home.arpa" }];
const card = replaced => ({ ssid: "Home", password: "ABCD EFGH", setup_replaced: replaced, qr: { size: 1, modules: "1" } });
const submit = (el, id) => el[id].listeners.submit({ preventDefault() {} });
const shownOnly = (el, ids) => {
  for (const id of ["net-new", "net-kept", "net-once", "rejoin"]) assert.equal(el[id].hidden, !ids.includes(id), id);
};

const cases = {
  // The first enrolment: the code, and the Owner network shown once.
  async first() {
    const { el } = run(factoryHTML, { "/enrol/begin": begin, "/enrol/finish": [200, { recovery: "ABCD-EFGH", network: card(true) }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "");
    assert.equal(el.enrol.hidden, true);
    assert.equal(el.shown.hidden, false);
    assert.equal(el["recovery-box"].hidden, false);
    assert.equal(el.recovery.textContent, "ABCD-EFGH");
    assert.equal(el.network.hidden, false);
    shownOnly(el, ["net-new", "net-once", "rejoin"]);
    assert.equal(el.ssid.textContent, "Home");
    assert.equal(el.password.textContent, "ABCD EFGH");
    assert.equal(el.qr.children.length, 1);
    el.last4.listeners.input({ target: { value: "xxxx" } });
    assert.equal(el.joined.hidden, true);
    el.last4.listeners.input({ target: { value: "e fgh" } });
    assert.equal(el.joined.hidden, false);
  },
  // A first enrolment whose save failed after the setup network went:
  // the card alone, not "shown only now", and how to enrol again.
  async firstFailed() {
    const { el } = run(factoryHTML, { "/enrol/begin": begin, "/enrol/finish": [500, { error: "Disk full", network: card(true) }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "Not enrolled: Disk full. Save the network below, join it, open this page again and enrol with the same code.");
    assert.equal(el.enrol.hidden, true);
    assert.equal(el["recovery-box"].hidden, true);
    assert.equal(el.network.hidden, false);
    shownOnly(el, ["net-new", "rejoin"]);
  },
  // A failure with no card (a retry from the Owner network, #4929 R-UX4):
  // the form stays, ready for another try.
  async failed() {
    const { el } = run(factoryHTML, { "/enrol/begin": begin, "/enrol/finish": [500, { error: "Disk full" }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "Not enrolled: Disk full");
    assert.equal(el.enrol.hidden, false);
    assert.equal(el.enrol.button.disabled, false);
    assert.equal(el.shown.hidden, true);
  },
  // A retry that works after one that failed: the failure's words go.
  async failedThenEnrolled() {
    const { el } = run(factoryHTML, { "/enrol/begin": begin,
      "/enrol/finish": [[500, { error: "Disk full" }], [200, { recovery: "ABCD-EFGH", network: card(true) }]] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "Not enrolled: Disk full");
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "");
    assert.equal(el.recovery.textContent, "ABCD-EFGH");
  },
  // A recovery: the code and when the replacement applies, no card.
  async recovery() {
    const { el } = run(factoryHTML, { "/enrol/begin": begin, "/enrol/finish": [200, { recovery: "ABCD-EFGH", due: "10:10" }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "");
    assert.equal(el.due.textContent, "Your new passkey replaces the old one at 10:10. Come back to this page after that to finish.");
    assert.equal(el.network.hidden, true);
  },
  // After a factory reset the owner is on the Owner network already.
  async afterReset() {
    const { el } = run(resetHTML, { "/enrol/begin": begin, "/enrol/finish": [200, { recovery: "ABCD-EFGH", network: card(false) }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "");
    assert.equal(el.enrol.hidden, true);
    shownOnly(el, ["net-kept", "net-once"]);
  },
  async afterResetFailed() {
    const { el } = run(resetHTML, { "/enrol/begin": begin, "/enrol/finish": [500, { error: "Disk full", network: card(false) }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "Not enrolled: Disk full");
    assert.equal(el.enrol.hidden, false);
    assert.equal(el.enrol.button.disabled, false);
    assert.equal(el.network.hidden, true);
  },
  async resetRefused() {
    const { el, ctx } = run(enrolledHTML, { "/enrol/reset": [403, { error: "wrong code" }] });
    await submit(el, "reset");
    assert.equal(el.result.textContent, "Not reset: wrong code");
    assert.equal(ctx.reloaded, undefined);
  },
  async resetDone() {
    const { el, ctx } = run(enrolledHTML, { "/enrol/reset": [200, { done: true }] });
    await submit(el, "reset");
    assert.equal(ctx.reloaded, true);
  },
  // Revoking the core's key cannot be undone, so the button asks first;
  // declined, nothing is posted and no tap is asked for (#4751).
  async revokeDeclined() {
    const { acts, posted } = run(homeHTML, {}, false);
    const b = acts.find(b => b.dataset.action === "revoke-core");
    assert.ok(b.dataset.confirm);
    await b.listeners.click();
    assert.deepEqual(posted, []);
    assert.equal(b.disabled, false);
  },
  async revokeConfirmed() {
    const { acts, posted, ctx } = run(homeHTML, { "/challenge": begin, "/act": [200, { done: true }] });
    await acts.find(b => b.dataset.action === "revoke-core").listeners.click();
    assert.deepEqual(posted, ["/challenge", "/act"]);
    assert.equal(ctx.reloaded, true);
  },
  // A step that can be undone asks nothing before the tap.
  async clearAsksNothing() {
    const { acts, posted } = run(homeHTML, { "/challenge": begin, "/act": [200, { done: true }] }, false);
    const b = acts.find(b => b.dataset.action === "clear");
    assert.equal(b.dataset.confirm, undefined);
    await b.listeners.click();
    assert.deepEqual(posted, ["/challenge", "/act"]);
  },
};

// A case whose page.js promise never settles leaves Node nothing to wait
// on, so it exits early with the rest unrun: count the cases that ended.
let ended = 0;
process.on("exit", () => {
  if (ended !== Object.keys(cases).length) {
    console.error(`${ended} of ${Object.keys(cases).length} cases ended`);
    process.exitCode = 1;
  }
});
(async () => {
  for (const [name, f] of Object.entries(cases)) {
    try { await f(); } catch (e) { console.error(name + ": " + e.message); process.exitCode = 1; }
    ended++;
  }
})();
