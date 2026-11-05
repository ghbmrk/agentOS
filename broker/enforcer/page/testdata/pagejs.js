// Runs static/page.js against a stub DOM built from the enrolment screen
// the server rendered (#4929 R-P1), and asserts what the owner is shown.
// An id page.js reads that the screen lacks is null here, as in a browser.
//
//   node pagejs.js page.js factory.html reset.html enrolled.html
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const [script, factoryHTML, resetHTML, enrolledHTML] = process.argv.slice(2).map(p => fs.readFileSync(p, "utf8"));

// dom is a flat stub of html's elements: each tag with an id, a form's
// button and named inputs, and its hidden attribute.
function dom(html) {
  const byId = {}, forms = [];
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
    const rp = attr("data-rp");
    if (rp !== null) el.dataset.rp = rp;
    if (el.id) byId[el.id] = el;
    if (tag === "form") { forms.push(el); form = el; }
    if (form && tag === "button") form.button = el;
    if (form && tag === "input" && attr("name")) form.elements[attr("name")] = el;
  }
  return { byId, forms };
}

// run loads page.js on html with fetch answering answers[path] as
// [status, body], and returns the stub elements.
function run(html, answers) {
  const { byId, forms } = dom(html);
  let ready = null;
  const cred = { rawId: new ArrayBuffer(1), response: {
    getPublicKeyAlgorithm: () => -7, getPublicKey: () => new ArrayBuffer(1),
    authenticatorData: new ArrayBuffer(1), clientDataJSON: new ArrayBuffer(1), signature: new ArrayBuffer(1) } };
  const ctx = {
    document: {
      getElementById: id => byId[id] || null,
      querySelectorAll: s => s === "form" ? forms : [],
      querySelector: () => ({ content: "token" }),
      addEventListener: (t, f) => { ready = f; },
      createElementNS: () => ({ setAttribute() {} }),
    },
    navigator: { credentials: { create: async () => cred, get: async () => cred } },
    crypto: { getRandomValues: a => a },
    atob: s => Buffer.from(s, "base64").toString("binary"),
    btoa: s => Buffer.from(s, "binary").toString("base64"),
    fetch: async path => {
      const [status, body] = answers[path];
      return { ok: status === 200, status, statusText: "", json: async () => body };
    },
    confirm: () => true,
    location: { reload() { ctx.reloaded = true; }, hash: "" },
    Uint8Array, ArrayBuffer, Error, String, JSON,
  };
  vm.runInNewContext(script, ctx);
  ready();
  return { el: byId, ctx };
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
  // A recovery: the code and when the replacement applies, no card.
  async recovery() {
    const { el } = run(factoryHTML, { "/enrol/begin": begin, "/enrol/finish": [200, { recovery: "ABCD-EFGH", due: "10:10" }] });
    await submit(el, "enrol");
    assert.equal(el.result.textContent, "");
    assert.match(el.due.textContent, /at 10:10\./);
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
};

(async () => {
  for (const [name, f] of Object.entries(cases)) {
    try { await f(); } catch (e) { console.error(name + ": " + e.message); process.exitCode = 1; }
  }
})();
