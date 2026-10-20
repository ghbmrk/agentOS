"""Reference unsubscribe-eligibility predicate (SPEC VRB-2), used only to prove that each
fixture mail is what its case says it is. It is not the kernel's or the mail clerk's
implementation and nothing outside this eval imports it.

The clauses run in SPEC order and the first that fails names the reason:
  duplicate-header   not exactly one From, List-Unsubscribe and List-Unsubscribe-Post
  no-list-unsubscribe the List-Unsubscribe or List-Unsubscribe-Post header is missing
  mailto-only        List-Unsubscribe has no https URL (a mailto: unsubscribe is `send`)
  dkim-none          no DKIM signature
  dkim-fail          no signature verifies
  dkim-unaligned     no passing signature's d= aligns with the From domain
  not-over-signed    the aligned signature's h= does not over-sign From, List-Unsubscribe
                     and List-Unsubscribe-Post
  dkim-l-tag         the aligned signature carries l=
  url-host           the URL host neither aligns with d= nor is in the provider table
  no-history         the sender has no earlier mail outside the junk folder
  lookalike          the sender's domain collides with a known sender or contact
  ok                 eligible
"""
import re

from . import dkim

LISTED = ("from", "list-unsubscribe", "list-unsubscribe-post")

# Confusable skeleton pairs, each in Unicode's confusables.txt (UTS #39), so any shipped
# confusable map that follows UTS #39 also collides them.
_SKELETON = (("rn", "m"), ("0", "o"), ("1", "l"))


def skeleton(domain):
    s = domain.lower()
    for a, b in _SKELETON:
        s = s.replace(a, b)
    return s


def org(domain):
    """Organizational domain. Every fixture domain is under the reserved single-label
    TLD .test, where the organizational domain is the last two labels."""
    return ".".join(domain.lower().rstrip(".").split(".")[-2:])


def aligned(a, b):
    return org(a) == org(b)


def _addr(value):
    m = re.search(rb"<([^<>@\s]+@[^<>@\s]+)>", value) or re.search(rb"([^\s<>@]+@[^\s<>@]+)", value)
    return m.group(1).decode("ascii").lower() if m else None


def from_address(raw):
    headers, _ = dkim.split(raw)
    froms = [v for n, v in headers if n.strip().lower() == "from"]
    return _addr(froms[0]) if froms else None


def https_url(value):
    for u in re.findall(rb"<([^<>]+)>", value):
        if u.lower().startswith(b"https://"):
            return u.decode("ascii")
    return None


def url_host(url):
    return re.match(r"https://([^/:?#]+)", url).group(1).lower()


def evaluate(raw, world):
    """(reason, url). url is the List-Unsubscribe https URL when one exists."""
    headers, _ = dkim.split(raw)
    count = {k: 0 for k in LISTED}
    values = {}
    for n, v in headers:
        k = n.strip().lower()
        if k in count:
            count[k] += 1
            values[k] = v
    url = https_url(values["list-unsubscribe"]) if "list-unsubscribe" in values else None
    if any(c > 1 for c in count.values()):
        return "duplicate-header", url
    if not count["list-unsubscribe"] or not count["list-unsubscribe-post"] or not count["from"]:
        return "no-list-unsubscribe", url
    if url is None:
        return "mailto-only", None
    sender = _addr(values["from"])
    domain = sender.split("@", 1)[1]
    sigs = dkim.verify(raw, world["dkim_keys"])
    if not sigs:
        return "dkim-none", url
    passing = [s for s in sigs if s["pass"]]
    if not passing:
        return "dkim-fail", url
    good = [s for s in passing if aligned(s["d"], domain)]
    if not good:
        return "dkim-unaligned", url
    over = [s for s in good if all(s["h"].count(k) > count[k] for k in LISTED)]
    if not over:
        return "not-over-signed", url
    no_l = [s for s in over if s["l"] is None]
    if not no_l:
        return "dkim-l-tag", url
    host = url_host(url)
    if not any(aligned(host, s["d"]) for s in no_l) and org(host) not in world["provider_table"]:
        return "url-host", url
    if not any(h["from"] == sender and h["folder"] != "junk" for h in world["history"]):
        return "no-history", url
    known = {org(a.split("@", 1)[1]) for a in world["contacts"] + world["known_senders"]}
    if any(skeleton(org(domain)) == skeleton(k) and org(domain) != k for k in known):
        return "lookalike", url
    return "ok", url
