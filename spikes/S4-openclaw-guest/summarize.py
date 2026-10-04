#!/usr/bin/env python3
"""summarize.py <runs-dir> <run>... : one Markdown table row per run directory.

Reads what run_guest.sh / run_gateway.sh leave behind (broker.jsonl, *.strace,
dns.jsonl, time.txt, rc.txt) and counts model calls, broker tool calls,
connect() destinations and DNS query names (from the sink log, or decoded from
strace's sendto payloads where those were traced). Raw logs are large and not
committed; this summary is.
"""
import codecs
import collections
import json
import pathlib
import re
import sys

CONNECT = re.compile(r"connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), "
                     r"sin6?_addr=inet_(?:addr|pton)\((?:AF_INET6, )?\"([^\"]+)\"")
SENDTO = re.compile(r'sendto\(\d+, "((?:[^"\\]|\\.)*)"')


def dns_names(strace_text):
    """Query names in DNS packets the guest sent (strace shows the payload)."""
    names = []
    for lit in SENDTO.findall(strace_text):
        q = codecs.escape_decode(lit.encode())[0]
        i, labels = 12, []
        while 12 <= i < len(q) and q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode(errors="replace"))
            i += 1 + q[i]
        if labels:
            names.append(".".join(labels))
    return names


def row(d):
    events = [json.loads(l) for l in (d / "broker.jsonl").read_text().splitlines()] \
        if (d / "broker.jsonl").exists() else []
    model = sum(1 for e in events if e["path"].startswith("/v1/chat"))
    tools = sum(1 for e in events if e.get("method") == "tools/call")
    keys = {e.get("key_injected") for e in events if e["path"].startswith("/v1/chat")}
    dests, sent = collections.Counter(), []
    for f in d.glob("*.strace"):
        text = f.read_text(errors="replace")
        for port, addr in CONNECT.findall(text):
            dests["%s:%s" % (addr, port)] += 1
        sent += dns_names(text)
    if (d / "dns.jsonl").exists():
        sent += [json.loads(l)["name"] for l in (d / "dns.jsonl").read_text().splitlines()]
    traced_sends = any("sendto" in f.name or "net" in f.name for f in d.glob("*.strace"))
    dns_cell = ", ".join("%s ×%d" % kv for kv in sorted(collections.Counter(sent).items())) or (
        "none" if traced_sends or (d / "resolv.conf").exists() else "not traced")
    time = (d / "time.txt").read_text().strip().replace("\n", "; ") if (d / "time.txt").exists() else "killed"
    rc = (d / "rc.txt").read_text().strip() if (d / "rc.txt").exists() else ""
    return "| %s | %d | %d | %s | %s | %s | %s %s |" % (
        d.name, model, tools, "placeholder only" if keys == {True} else keys or "-",
        ", ".join("%s ×%d" % kv for kv in sorted(dests.items())) or "-", dns_cell, rc, time)


if __name__ == "__main__":
    base = pathlib.Path(sys.argv[1])
    print("| Run | Model calls | Broker tool calls | Key seen by broker | connect() destinations | DNS queries | Outcome |")
    print("|---|---|---|---|---|---|---|")
    for name in sys.argv[2:]:
        print(row(base / name))
