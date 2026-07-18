# logtail-alert

Spot SSH brute-force attacks in an auth log — in one command, no dependencies.

`logtail-alert` reads an authentication log (default `/var/log/auth.log`), finds
failed-login events, and flags any source IP that racks up too many failures too
fast. That burst pattern — lots of failures from one IP in a short window,
usually against many usernames — is the signature of a brute-force or
password-spray attack. Think of it as the *detection* half of `fail2ban`,
without the firewall part.

## Demo

<!-- Record a scan of sample.log plus a live --follow alert, then drop the file
     here. Replace this line with:  ![logtail-alert demo](demo.gif) -->

_Demo GIF coming soon._

## Why

Auth logs are noisy, and a slow brute-force is easy to miss by eye. A simple
sliding-window counter turns "thousands of log lines" into "these two IPs are
attacking you." It's a great first blue-team tool: the whole detection idea fits
in one readable class.

## Install

```bash
git clone https://github.com/<you>/logtail-alert
cd logtail-alert
```

No pip install — Python 3 standard library only.

## Try it right now

A `sample.log` is included, with a brute-force burst hidden in normal traffic:

```bash
python3 logtail-alert.py sample.log
```

```
== logtail-alert: sample.log ==
threshold: 5 fails / 60s

[ALERT] 45.9.1.7 — 5 failed logins in 16.0s  (users: admin, oracle, root, test)

top sources of failed logins:
  IP                    fails  users  flagged
  45.9.1.7                  8      6  YES
  10.0.2.9                  1      1  -
  203.0.113.4               1      1  -
  198.51.100.22             1      1  -
```

## Usage

```bash
python3 logtail-alert.py                         # scan /var/log/auth.log
python3 logtail-alert.py /var/log/auth.log
python3 logtail-alert.py -n 5 -w 60              # 5 fails within 60s = alert
python3 logtail-alert.py --follow                # live tail, alert in real time
python3 logtail-alert.py sample.log --json       # one JSON object per alert
```

### Options

| Flag | Meaning |
|---|---|
| `-n, --threshold` | failures from one IP that trigger an alert (default 5) |
| `-w, --window` | time window in seconds for the threshold (default 60) |
| `-f, --follow` | tail the log live instead of a one-shot scan |
| `--json` | emit JSON, one object per alert |

## What it detects

Failed-login lines from OpenSSH and PAM, including:

- `Failed password for <user> from <ip>`
- `Failed password for invalid user <user> from <ip>`
- `Invalid user <user> from <ip>`
- `authentication failure; ... rhost=<ip> user=<user>`

An IP is flagged when it produces **`threshold` failures within `window`
seconds** (a sliding window, so it catches slow-and-steady attacks too).

## Exit codes

- `0` — no IP crossed the threshold
- `1` — at least one IP was flagged (wire it into monitoring / cron)

## How it works

Each failed login is parsed into `(ip, user, timestamp)`. Per IP, timestamps go
into a sliding window (a `deque`); anything older than `window` seconds is
dropped. The moment the window holds `threshold` or more failures, the IP is
alerted once — and it can alert again if it cools off and flares up later.

## Notes

- Reading `/var/log/auth.log` usually needs `sudo` (or membership in the `adm`
  group). The bundled `sample.log` needs neither.
- Detection only — it does not block anything. Pair it with `iptables`/`ufw` or
  `fail2ban` if you want automated response.

## License

MIT
