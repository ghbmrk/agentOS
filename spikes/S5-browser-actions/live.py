#!/usr/bin/env python3
"""Drive 5 real sites through the v0 protocol only; append results to results.jsonl.

  live.py [site ...]        default: all five

Each task is a scripted agent: it sees only protocol responses and picks refs by role
and accessible name. Logins use each site's own published demo credentials and happen
out of band (owner live view, CH-8); no real account is used.
"""
import json
import os
import pathlib
import re
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from client import Session, StepFailed, find  # noqa: E402
from executor import CHROME  # noqa: E402

RESULTS = HERE / "results.jsonl"


def owner_login(url, fields, submit, state_path):
    """Stand-in for the owner's live-view login: outside the protocol, never logged."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        px = os.environ.get("S5_PROXY") or os.environ.get("HTTPS_PROXY")
        b = p.chromium.launch(executable_path=CHROME, **({"proxy": {"server": px}} if px else {}))
        c = b.new_context()
        pg = c.new_page()
        pg.goto(url)
        for sel, val in fields:
            pg.fill(sel, val)
        pg.click(submit)
        pg.wait_for_load_state("networkidle")
        c.storage_state(path=str(state_path))
        b.close()


def chromium_pss_mb(pid):
    """PSS of the Chromium processes under the executor (shared pages counted once)."""
    kids = {}
    for d in pathlib.Path("/proc").iterdir():
        if d.name.isdigit():
            try:
                ppid = int((d / "stat").read_text().rsplit(")", 1)[1].split()[1])
                kids.setdefault(ppid, []).append(int(d.name))
            except (OSError, IndexError, ValueError):
                pass
    total, todo = 0, [pid]
    while todo:
        p = todo.pop()
        todo += kids.get(p, [])
        try:
            if not re.search(r"chrom|headless", pathlib.Path(f"/proc/{p}/comm").read_text()):
                continue
            m = re.search(r"Pss:\s+(\d+)", pathlib.Path(f"/proc/{p}/smaps_rollup").read_text())
            total += int(m.group(1)) if m else 0
        except OSError:
            pass
    return round(total / 1024)


def find_in(s, role, name):
    return find(s.snap["snapshot"], role, name)


# --- tasks: each returns {"check": <evidence string>} or raises StepFailed -----

def wikipedia(s):
    s.do("navigate", url="https://en.wikipedia.org/wiki/Main_Page")
    s.look()
    s.do("type", ref=s.ref("searchbox", "Search"), text="Alan Turing", submit=True)
    snap = s.look()["snapshot"]
    if "Alan Turing" not in s.snap["title"]:
        raise StepFailed(f"landed on {s.snap['title']}")
    born = re.search(r"Born[^\n]*\n[^\n]*?(\d{1,2} June 1912)", snap)
    s.do("click", ref=s.ref("link", "^View history$"))
    s.look()
    if "history" not in s.snap["title"].lower():
        raise StepFailed("history page not reached")
    return {"check": f"born={born.group(1) if born else '?'}; history page reached"}


def govuk(s):
    s.do("navigate", url="https://www.gov.uk/check-uk-visa")
    s.look()
    start = (find_in(s, "button", "Start now") or find_in(s, "link", "Start now"))[0]
    s.do("click", ref=start)
    s.look()
    combo = (s.snap["snapshot"])
    if "combobox" in combo:
        s.do("select", ref=s.ref("combobox"), option="Kenya")
    else:
        raise StepFailed("no nationality control")
    s.look()
    s.do("click", ref=s.ref("button", "Continue"))
    s.look()
    # The checker asks a variable number of radio questions; answer each by its heading.
    answers = [("coming to the UK", "Tourism"), ("how long|stay", "6 months or less")]
    seen = []
    for _ in range(8):
        h = re.search(r'heading "([^"]+)" \[level=1\]', s.snap["snapshot"])
        title = h.group(1) if h else ""
        seen.append(title)
        if "radio" not in s.snap["snapshot"]:
            break
        name = next((a for pat, a in answers if re.search(pat, title, re.I)), "No")
        s.do("click", ref=s.ref("radio", f"^{re.escape(name)}"))
        s.do("click", ref=s.ref("button", "Continue"))
        s.look()
    if not re.search(r"visa|permission|eta|entry", seen[-1], re.I):
        raise StepFailed(f"no outcome heading; questions: {seen}")
    return {"check": f"outcome '{seen[-1][:60]}' after {len(seen) - 1} questions"}


def saucedemo(s):
    s.do("navigate", url="https://www.saucedemo.com/inventory.html")
    s.look()
    s.do("select", ref=s.ref("combobox"), option="Price (low to high)")
    s.look()
    s.do("click", ref=s.ref("button", "Add to cart", 0))
    s.look()
    s.do("navigate", url="https://www.saucedemo.com/cart.html")
    s.look()
    s.do("click", ref=s.ref("button", "Checkout"))
    s.look()
    for name, val in (("First Name", "Test"), ("Last Name", "Synthetic"), ("Zip", "00000")):
        s.do("type", ref=s.ref("textbox", name), text=val)
    s.do("click", ref=s.ref("button", "Continue"))
    s.look()
    s.do("click", ref=s.ref("button", "Finish"))
    snap = s.look()["snapshot"]
    if "Thank you for your order" not in snap:
        raise StepFailed("no confirmation")
    return {"check": "Thank you for your order!"}


def herokuapp(s):
    base = "https://the-internet.herokuapp.com"
    out = []
    s.do("navigate", url=base + "/secure")
    if "secure area" not in s.look()["snapshot"].lower():
        raise StepFailed("session not carried into executor")
    out.append("secure area via owner session")
    s.do("navigate", url=base + "/dropdown")
    s.look()
    s.do("select", ref=s.ref("combobox"), option="Option 2")
    out.append("dropdown")
    s.do("navigate", url=base + "/download")
    s.look()
    res = s.do("download", ref=s.ref("link", r"^test\.txt$"))
    out.append(f"download {res['bytes']} B")
    s.do("navigate", url=base + "/shadowdom")
    if "My default text" not in s.look()["snapshot"] and "Let's have some different text" not in s.snap["snapshot"]:
        raise StepFailed("shadow DOM text not in snapshot")
    out.append("shadow DOM read")
    s.do("navigate", url=base + "/dynamic_loading/2")
    s.look()
    s.do("click", ref=s.ref("button", "Start"))
    for _ in range(10):
        if "Hello World!" in s.look()["snapshot"]:
            break
        time.sleep(1)
    else:
        raise StepFailed("dynamic content never appeared")
    out.append("dynamic load")
    return {"check": "; ".join(out)}


def herokuapp_gaps(s):
    """Patterns expected to need verbs v0 lacks; failures here are findings, not bugs."""
    base = "https://the-internet.herokuapp.com"
    found = {}
    s.do("navigate", url=base + "/javascript_alerts")
    s.look()
    s.do("click", ref=s.ref("button", "JS Confirm"))
    m = re.search(r"You clicked: \w+", s.look()["snapshot"])
    found["confirm_dialog"] = m.group(0) if m else "no result"
    s.do("navigate", url=base + "/hovers")
    snap = s.look()["snapshot"]
    found["hover_menu"] = "visible without hover" if "name: user1" in snap else "hidden (needs hover)"
    s.do("navigate", url=base + "/upload")
    snap = s.look()["snapshot"]
    found["file_upload"] = "no verb (button present)" if "button" in snap else "?"
    return {"check": json.dumps(found)}


def github(s):
    s.do("navigate", url="https://github.com/ghbmrk/agentOS")
    s.look()
    s.do("click", ref=s.ref("link", "^Pull requests"))
    s.look()
    time.sleep(3)  # the PR list renders client-side after load
    snap = s.look()["snapshot"]
    first = re.search(r'link "([^"]{10,})"[^\n]*\n\s+- /url: (?:https://github.com)?/ghbmrk/agentOS/pull/\d+', snap)
    if not first:
        raise StepFailed("no pull request link in snapshot")
    s.do("navigate", url="https://github.com/ghbmrk/agentOS/blob/main/README.md")
    s.look()
    # The "Download raw file" button did not produce a download event in the 2026-10-09 run
    # (it is script-driven); the "Raw" link navigates to the second declared origin instead.
    s.do("click", ref=s.ref("link", "^Raw$"))
    s.look()
    if "raw.githubusercontent.com" not in s.snap["url"]:
        raise StepFailed(f"raw link landed on {s.snap['url']}")
    return {"check": f"first PR '{first.group(1)[:40]}'; raw README on {s.snap['url'].split('/')[2]}"}


SITES = {
    "wikipedia": (wikipedia, ["https://en.wikipedia.org"], None),
    "govuk": (govuk, ["https://www.gov.uk"], None),
    "saucedemo": (saucedemo, ["https://www.saucedemo.com"], "saucedemo"),
    "herokuapp": (herokuapp, ["https://the-internet.herokuapp.com"], "herokuapp"),
    "herokuapp_gaps": (herokuapp_gaps, ["https://the-internet.herokuapp.com"], None),
    "github": (github, ["https://github.com", "https://raw.githubusercontent.com"], None),
}


def run(name):
    task, origins, login = SITES[name]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        state = None
        if login:
            login = json.loads((HERE / "demo_logins.json").read_text())[login]
            login = (login["url"], login["fields"], login["submit"])
            state = tmp / "owner-state.json"
            owner_login(*login, state)
        s = Session(origins, tmp / "ws", state)
        t0 = time.monotonic()
        rec = {"site": name, "origins": origins}
        try:
            rec.update(task(s), ok=True)
        except StepFailed as e:
            rec.update(ok=False, failure=str(e)[:300])
        rec["seconds"] = round(time.monotonic() - t0, 1)
        rec["chromium_pss_mb"] = chromium_pss_mb(s.proc.pid)
        rec["steps"] = len(s.log)
        rec["verbs"] = sorted({e["req"]["verb"] for e in s.log})
        rec["redactions"] = sum(e["res"].get("redactions", 0) for e in s.log)
        rec["refused"] = [u for e in s.log for u in e["res"].get("refused_navigations", [])]
        rec["errors"] = [f"{e['req']['verb']}: {e['res'].get('error')}" for e in s.log
                         if not e["res"].get("ok")]
        rec["ms_by_verb"] = {}
        for e in s.log:
            rec["ms_by_verb"].setdefault(e["req"]["verb"], []).append(e["res"].get("ms"))
        s.close()
        if state:
            rec["password_in_output"] = login[1][-1][1] in "".join(s.raw)
    rec["chromium"] = os.path.basename(os.path.dirname(os.path.dirname(CHROME)))
    with RESULTS.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


if __name__ == "__main__":
    for name in sys.argv[1:] or SITES:
        print(json.dumps(run(name)))
