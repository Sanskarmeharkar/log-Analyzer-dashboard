"""Access-log analyser using regular expressions (core engine + command line).
CLI : python access_log_analyzer.py --check "<line>" | <logfile> | --interactive
Web : python server.py   (dashboard uses the functions below through a JSON API)
"""
import re, argparse
from collections import Counter

# ---- Regular expressions ----
OCTET   = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4    = r"(" + OCTET + r"\.){3}" + OCTET                       # RE-1
TIME    = r"\d{2}/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}" \
          r":([01]\d|2[0-3]):[0-5]\d:[0-5]\d [+-]\d{4}"          # RE-2
METHOD  = r"(GET|POST|PUT|DELETE|HEAD)"                          # RE-3
STATUS  = r"[1-5]\d\d"                                           # RE-4
ERRCODE = r"[45]\d\d"                                            # RE-5 (Step 3 NFA/DFA)
REGEXES = {"RE-1 IPv4 address": IPV4, "RE-2 Timestamp": TIME, "RE-3 HTTP method": METHOD,
           "RE-4 Status code": STATUS, "RE-5 Failed-request code": ERRCODE}

LINE = re.compile(
    r"^(?P<ip>" + IPV4 + r") - - \[(?P<time>" + TIME + r")\] "
    r"\"(?P<method>" + METHOD + r") (?P<path>/\S*) HTTP/\d\.\d\" "
    r"(?P<status>" + STATUS + r") (?P<size>\d+|-)$")

def diagnose(line):
    if not re.match(IPV4 + r" ", line):              return "invalid IPv4 address"
    if not re.search(r"\[" + TIME + r"\]", line):    return "invalid timestamp"
    if not re.search(r"\"" + METHOD + r" ", line):   return "invalid HTTP method"
    return "invalid status code or wrong line format"

def check_data(line):
    line = line.strip()
    m = LINE.match(line)
    if not m:
        return {"valid": False, "reason": diagnose(line)}
    f = m.groupdict()
    return {"valid": True, "fields": {k: f[k] for k in ("ip", "time", "method", "path", "status", "size")},
            "failed": bool(re.fullmatch(ERRCODE, f["status"]))}

def analyze_text(text):
    lines = [l.rstrip("\r") for l in text.split("\n") if l.strip()]
    good, bad = [], []
    for n, l in enumerate(lines, 1):
        m = LINE.match(l.strip())
        if m: good.append({"n": n, **m.groupdict()})
        else: bad.append({"n": n, "line": l, "reason": diagnose(l)})
    failed = [r for r in good if re.fullmatch(ERRCODE, r["status"])]
    return {"total": len(lines), "valid": len(good), "invalid": len(bad), "failed_count": len(failed),
            "unique_ips": len({r["ip"] for r in good}),
            "failed": [{k: r[k] for k in ("n", "ip", "method", "path", "status")} for r in failed],
            "invalid_lines": bad,
            "status_counts": dict(sorted(Counter(r["status"] for r in good).items())),
            "ip_counts": dict(Counter(r["ip"] for r in failed).most_common())}

# ---- command line ----
def cli_check(line):
    d = check_data(line)
    print("Input  :", line.strip())
    if d["valid"]:
        print("Result : VALID")
        for k, v in d["fields"].items(): print(f"  {k:<7}: {v}")
        print("  failed :", "YES" if d["failed"] else "NO")
    else:
        print("Result : INVALID  (" + d["reason"] + ")")
    print()

def cli_file(path):
    r = analyze_text(open(path, encoding="utf-8").read())
    print("FAILED REQUESTS (4xx / 5xx)")
    for f in r["failed"]:
        print(f"  line {f['n']:<3}{f['ip']:<16}{f['method']:<7}{f['path']:<18}{f['status']}")
    print("\nINVALID LINES")
    for b in r["invalid_lines"]: print(f"  line {b['n']:<3}{b['line']}  -> {b['reason']}")
    print("\nSUMMARY")
    print("  Total lines     :", r["total"])
    print("  Valid / Invalid :", r["valid"], "/", r["invalid"])
    print("  Failed requests :", r["failed_count"])
    print("  Status counts   :", r["status_counts"])

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", nargs="?")
    ap.add_argument("--check"); ap.add_argument("--interactive", action="store_true")
    a = ap.parse_args()
    if a.check: cli_check(a.check)
    elif a.interactive:
        while (s := input("> ")).strip(): cli_check(s)
    elif a.logfile: cli_file(a.logfile)
    else: ap.print_help()
