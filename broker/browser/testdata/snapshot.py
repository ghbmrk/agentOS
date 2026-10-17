# Prints the AI aria snapshot Chromium gives for an HTML file, as the S5
# executor reads it: locator("body").aria_snapshot(mode="ai").
# Usage: python3 -I testdata/snapshot.py testdata/clicks.html > testdata/clicks.snapshot.txt
# Every request is answered with the file, so nothing leaves the machine.
# To map element ids to refs: python3 -I testdata/snapshot.py FILE --refs
import glob, sys
from playwright.sync_api import sync_playwright

html = open(sys.argv[1]).read()
exe = glob.glob("/opt/pw-browsers/chromium_headless_shell-*/chrome-linux/headless_shell")
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=exe[0] if exe else None)
    pg = b.new_page()
    pg.route("**/*", lambda r: r.fulfill(body=html, content_type="text/html"))
    pg.goto("https://shop.example.test/mail")
    snap = pg.locator("body").aria_snapshot(mode="ai")
    if "--refs" in sys.argv:
        for el in pg.query_selector_all("[id]"):
            i = el.get_attribute("id")
            for r in range(1, 200):
                ref = pg.locator("aria-ref=e%d" % r)
                if ref.count() == 1 and ref.evaluate("(e, i) => e.id === i", i):
                    print(i, "e%d" % r)
                    break
    else:
        print(snap)
    b.close()
