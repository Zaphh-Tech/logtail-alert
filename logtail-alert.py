#!/usr/bin/env python3
"""
logtail-alert — spot SSH brute-force attacks in an auth log.

Reads an authentication log (default /var/log/auth.log), finds failed-login
events, and flags any source IP that racks up too many failures too fast —
the signature of a brute-force or password-spray attack. Prints an alert the
moment an IP crosses the threshold and a ranked summary of the worst offenders.

Works two ways:
  * one-shot (default) — scan an existing log file and report
  * --follow           — tail the log live and alert in real time (like fail2ban's
                         detection half, minus the firewall part)

Usage:
    python3 logtail-alert.py                         # scan /var/log/auth.log
    python3 logtail-alert.py /var/log/auth.log
    python3 logtail-alert.py --threshold 5 --window 60
    python3 logtail-alert.py --follow                # live tail
    python3 logtail-alert.py sample.log --json

Standard library only — no pip install required.
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime


class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


def color(t, c, on=True):
    return f"{c}{t}{C.END}" if on else t


# ---- log line parsing ----------------------------------------------------

IP_RE = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{4,})"

# Lines that represent a failed authentication attempt.
FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP_RE),
    re.compile(r"Invalid user (?P<user>\S+) from " + IP_RE),
    re.compile(r"authentication failure;.*rhost=" + IP_RE + r"(?:\s+user=(?P<user>\S+))?"),
    re.compile(r"Connection closed by authenticating user (?P<user>\S+) " + IP_RE),
]

# Leading syslog timestamp, e.g. "Jul 18 13:00:01".
TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def parse_timestamp(line, default):
    """Parse the syslog timestamp; return epoch seconds or `default`."""
    m = TS_RE.match(line)
    if not m:
        return default
    try:
        # Syslog omits the year; prepend the current one so the parse is
        # unambiguous (and leap-day safe).
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        return dt.timestamp()
    except ValueError:
        return default


def parse_line(line, fallback_ts):
    """Return (ip, user, ts) for a failed login, or None."""
    for pat in FAIL_PATTERNS:
        m = pat.search(line)
        if m:
            ts = parse_timestamp(line, fallback_ts)
            user = m.groupdict().get("user") or "?"
            return (m.group("ip"), user, ts)
    return None


# ---- detection -----------------------------------------------------------

class BruteForceDetector:
    """Sliding-window counter: alert when an IP exceeds `threshold` fails
    within `window` seconds."""

    def __init__(self, threshold, window):
        self.threshold = threshold
        self.window = window
        self.times = defaultdict(deque)   # ip -> deque[ts]
        self.users = defaultdict(set)     # ip -> {usernames tried}
        self.totals = defaultdict(int)    # ip -> total failures seen
        self.alerted = set()              # ips currently in an alerted burst

    def feed(self, ip, user, ts):
        """Record one failure; return an alert dict if this crossed the line."""
        self.totals[ip] += 1
        self.users[ip].add(user)
        dq = self.times[ip]
        dq.append(ts)
        # Drop failures that fell out of the window.
        while dq and ts - dq[0] > self.window:
            dq.popleft()

        if len(dq) >= self.threshold:
            if ip not in self.alerted:
                self.alerted.add(ip)
                span = ts - dq[0]
                return {
                    "ip": ip,
                    "count": len(dq),
                    "window_seconds": round(span, 1),
                    "users": sorted(self.users[ip]),
                }
        else:
            # Burst cooled off — allow the IP to alert again later.
            self.alerted.discard(ip)
        return None

    def summary(self):
        rows = []
        for ip, total in self.totals.items():
            rows.append({
                "ip": ip,
                "total_failures": total,
                "distinct_users": len(self.users[ip]),
                "flagged": ip in self.alerted or total >= self.threshold,
            })
        return sorted(rows, key=lambda r: r["total_failures"], reverse=True)


# ---- output --------------------------------------------------------------

def emit_alert(a, on, as_json):
    if as_json:
        print(json.dumps({"type": "brute_force", **a}))
        return
    users = ", ".join(a["users"][:5]) + ("…" if len(a["users"]) > 5 else "")
    print(color(
        f"[ALERT] {a['ip']} — {a['count']} failed logins in "
        f"{a['window_seconds']}s  (users: {users})", C.RED + C.BOLD, on))


def print_summary(detector, on):
    rows = detector.summary()
    if not rows:
        print(color("no failed logins found.", C.GREY, on))
        return
    print(color("\ntop sources of failed logins:", C.BOLD, on))
    print(color(f"  {'IP':<20}{'fails':>7}{'users':>7}  flagged", C.GREY, on))
    for r in rows[:15]:
        flag = color("YES", C.RED + C.BOLD, on) if r["flagged"] else "-"
        line = f"  {r['ip']:<20}{r['total_failures']:>7}{r['distinct_users']:>7}  "
        print(color(line, C.YELLOW if r["flagged"] else C.GREY, on) + flag)


# ---- sources -------------------------------------------------------------

def scan_file(path, detector, on, as_json):
    try:
        f = open(path, "r", errors="replace")
    except OSError as e:
        sys.exit(f"error: cannot open {path}: {e}")
    with f:
        for i, line in enumerate(f):
            ev = parse_line(line, fallback_ts=i)
            if ev:
                a = detector.feed(*ev)
                if a:
                    emit_alert(a, on, as_json)


def follow_file(path, detector, on, as_json):
    """Tail the file, processing new lines as they're appended."""
    try:
        f = open(path, "r", errors="replace")
    except OSError as e:
        sys.exit(f"error: cannot open {path}: {e}")
    with f:
        f.seek(0, 2)  # jump to end; only watch new activity
        if not as_json:
            print(color(f"following {path} — Ctrl-C to stop\n", C.GREY, on))
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            ev = parse_line(line, fallback_ts=time.time())
            if ev:
                a = detector.feed(*ev)
                if a:
                    emit_alert(a, on, as_json)


# ---- main ----------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Detect SSH brute-force attacks in an auth log."
    )
    ap.add_argument("logfile", nargs="?", default="/var/log/auth.log",
                    help="auth log to read (default /var/log/auth.log)")
    ap.add_argument("-n", "--threshold", type=int, default=5,
                    help="failures from one IP that trigger an alert (default 5)")
    ap.add_argument("-w", "--window", type=int, default=60,
                    help="time window in seconds for the threshold (default 60)")
    ap.add_argument("-f", "--follow", action="store_true",
                    help="tail the log live instead of a one-shot scan")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON (one object per alert)")
    args = ap.parse_args()

    on = sys.stdout.isatty() and not args.json
    # Line-buffer stdout so live alerts appear immediately when piped/redirected.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    detector = BruteForceDetector(args.threshold, args.window)

    if not args.json:
        print(color(f"\n== logtail-alert: {args.logfile} ==", C.BOLD + C.CYAN, on))
        print(color(f"threshold: {args.threshold} fails / {args.window}s\n",
                    C.GREY, on))

    if args.follow:
        try:
            follow_file(args.logfile, detector, on, args.json)
        except KeyboardInterrupt:
            if not args.json:
                print_summary(detector, on)
            sys.exit(130)
    else:
        scan_file(args.logfile, detector, on, args.json)
        if not args.json:
            print_summary(detector, on)
        # CI-friendly: non-zero exit if any IP was flagged.
        sys.exit(1 if detector.alerted else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
