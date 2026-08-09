#!/usr/bin/env python3
"""gwm_au.py - a command-line probe for the GWM ANZ (Australia / New Zealand) cloud API.

WARNING: AU/NZ ("aus" region) ONLY, and an R&D / debugging tool - NOT part of the add-on.
    It is a standalone Python re-implementation of the AU `bt-auth` request signing used by
    moryoav/ha-gwm_ora, written while reverse-engineering the ANZ API. It does NOT work for
    the EU region (EU uses a mutual-TLS client certificate, not bt-auth).
    Protocol reference: addons/gwm_ora/docs/AU_NZ_DEVELOPER_NOTES.md in that repo.

Usage (run `login` in your OWN terminal - it prompts for the password):
  python gwm_au.py login --email you@example.com [--region NZ]  # full/refresh login (pw + emailed code)
  python gwm_au.py whoami                        # getUserBaseInfo (cheap auth check)
  python gwm_au.py status                        # vehicles + last status (SoC, range, charging, plug)
  python gwm_au.py checkpin                       # validate the 6-digit control PIN (non-actuating)
  python gwm_au.py climate on|off [--temp N] [--minutes N] [--precheck]
  python gwm_au.py door lock|unlock [--no-precheck]
  python gwm_au.py cmdresult                      # send A/C-on, read result via getRemoteCtrlResultT5 (+vin header)
  python gwm_au.py cmd-probe                      # READ-ONLY remote-command subsystem probe
  python gwm_au.py sigtest <ep> <query>           # try GET query-signing canonicalizations
  python gwm_au.py set-pin --email you@example.com [--code CODE]   # set the control PIN
  python gwm_au.py get  "<path?query>"            # arbitrary signed GET  (probe)
  python gwm_au.py post "<path>" --json '<body>'  # arbitrary signed POST (probe); or --file body.json

Notes:
  - Tokens are cached in `gwm_token_v2.json` beside this script - keep it PRIVATE (git-ignore it);
    it grants access to the account. Passwords/PINs are read via getpass and never stored.
  - GWM allows ONE active session per account; a login here bumps the phone/app (and vice-versa).
    Use a dedicated account. `--region` must be the account's REGISTRATION country (e.g. NZ), not
    necessarily AU.
  - APP_KEY / APP_SEC below are the GWM app's public constants (already in the add-on source), not
    secrets.
  - GET signing rule: non-empty params sorted by original token, then lowercase(key)=value
    concatenated with NO separator; POST signs `json=`+body. Empty query params are dropped from
    both the URL and the signature.
"""
import argparse, getpass, hashlib, json, os, re, sys, time, uuid
from urllib.parse import quote_plus
from urllib.request import Request, urlopen
from urllib.error import HTTPError

BASE = os.environ.get("GWM_BASE", "https://aus-h5-gateway.gwmcloud.com"); API = "/app-api/api/v1.0/"
PREFIX = "bt"; APP_KEY = "2186661209"; APP_SEC = "a9664fd3f97665e202e73880de03a0d8"
TOKFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gwm_token_v2.json")
DEFAULT_DEV = "aabbccddeeff0011"
DEFAULT_EMAIL = None       # no baked-in account - pass --email
DEFAULT_REGION = "NZ"


def _sign(method, path, bj):
    ts = str(int(time.time() * 1000))
    nonce = hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:16]
    auth = f"{PREFIX}-auth-appkey:{APP_KEY}{PREFIX}-auth-nonce:{nonce}{PREFIX}-auth-timestamp:{ts}"
    if method == "POST":
        sign_path, params = path, ("json=" + bj if bj is not None else "")
    else:  # GET rule: NON-EMPTY pairs sorted by original token, SIGN = lowercase(key)=value CONCATENATED (no separator)
        if "?" in path:
            sign_path, q = path.split("?", 1)
            pairs = [(p.split("=", 1) + [""])[:2] for p in q.split("&") if p]
            pairs = [(k, v) for k, v in pairs if v != ""]
            pairs.sort(key=lambda kv: f"{kv[0]}={kv[1]}")           # sort by original token (Ordinal)
            params = "".join(f"{k.lower()}={v}" for k, v in pairs)  # lc key, NO '&' separator
        else:
            sign_path, params = path, ""
    raw = re.sub(r"\s*|\t|\r|\n", "", method + sign_path + auth + params + APP_SEC)
    return ts, nonce, hashlib.sha256(quote_plus(raw, safe="").encode()).hexdigest()


def call(method, path, body=None, region="NZ", access_token=None, dev=DEFAULT_DEV, extra_headers=None):
    if method == "GET" and "?" in path:  # drop empty params from URL too (match sig)
        base_path, q = path.split("?", 1)
        kept = sorted(p for p in q.split("&") if p and p.split("=", 1)[-1] != "")
        path = base_path + ("?" + "&".join(kept) if kept else "")
    bj = json.dumps(body, separators=(",", ":")) if body is not None else None
    ts, nonce, sg = _sign(method, path, bj)
    h = {"Accept": "application/json", "Content-Type": "application/json; charset=UTF-8",
         f"{PREFIX}-auth-appkey": APP_KEY, f"{PREFIX}-auth-timestamp": ts,
         f"{PREFIX}-auth-sign": sg, f"{PREFIX}-auth-nonce": nonce,
         "rs": "2", "appId": "1", "brand": "1", "terminal": "GW_APP_Haval", "enterpriseId": "CC01",
         "systemType": "1", "cVer": "1.0.0", "channel": "APP", "language": "en_US",
         "regionCode": region, "country": region, "deviceId": dev, "iccid": dev,
         "User-Agent": "Dart/3.3 (dart:io)"}
    if access_token is not None:
        h["accessToken"] = access_token
    if extra_headers:
        h.update(extra_headers)
    data = bj.encode() if bj is not None else None
    req = Request(BASE + path, data=data, headers=h, method=method)
    try:
        t = urlopen(req, timeout=25).read().decode("utf-8", "replace")
    except HTTPError as e:
        t = e.read().decode("utf-8", "replace")
    except Exception as e:
        return {"_error": str(e)}
    try:
        return json.loads(t)
    except Exception:
        return {"_raw": t[:600]}


def load_tokens():
    if not os.path.exists(TOKFILE):
        sys.exit(f"No {os.path.basename(TOKFILE)} - run `python gwm_au.py login --email ...` first.")
    return json.load(open(TOKFILE))


def save_tokens(s):
    json.dump(s, open(TOKFILE, "w"))


def session(refresh=True):
    """Return (accessToken, region, dev) from the saved token, refreshing first."""
    s = load_tokens()
    dev = s.get("deviceId", DEFAULT_DEV); region = s.get("region", "NZ")
    at = s["accessToken"]
    if refresh:
        r = call("POST", API + "userAuth/refreshToken",
                 {"accessToken": at, "refreshToken": s["refreshToken"], "deviceId": dev},
                 region, access_token=at, dev=dev)
        d = r.get("data") or {}
        if r.get("code") == "000000" and d.get("accessToken"):
            s["accessToken"] = at = d["accessToken"]
            if d.get("refreshToken"):
                s["refreshToken"] = d["refreshToken"]
            save_tokens(s)
        else:
            print(f"[refresh] {r.get('code')} {r.get('description')} (using saved token as-is)")
    return at, region, dev


def _vin(at, region, dev):
    for ep in ("vehicle/acquireVehicles", "globalapp/vehicle/acquireVehicles"):
        rv = call("GET", API + ep, None, region, access_token=at, dev=dev)
        data = rv.get("data")
        if rv.get("code") == "000000" and isinstance(data, list) and data:
            return data[0].get("vin") or data[0].get("vehicleId"), data[0]
    return None, None


def cmd_login(args):
    email = args.email or DEFAULT_EMAIL
    if not email:
        sys.exit("login requires --email <account e-mail>")
    email = email.strip()
    region = (args.region or DEFAULT_REGION).upper()
    print(f"login as {email} (region {region})")
    # refresh existing token if present and valid
    if os.path.exists(TOKFILE):
        s = json.load(open(TOKFILE))
        r = call("POST", API + "userAuth/refreshToken",
                 {"accessToken": s["accessToken"], "refreshToken": s["refreshToken"],
                  "deviceId": s.get("deviceId", DEFAULT_DEV)}, s.get("region", region),
                 access_token=s["accessToken"], dev=s.get("deviceId", DEFAULT_DEV))
        d = r.get("data") or {}
        if r.get("code") == "000000" and d.get("accessToken"):
            # verify it actually owns the session (single-session!)
            chk = call("GET", API + "user/getUserBaseInfo", None, s.get("region", region),
                       access_token=d["accessToken"], dev=s.get("deviceId", DEFAULT_DEV))
            if chk.get("code") == "000000":
                s["accessToken"] = d["accessToken"]; s["refreshToken"] = d.get("refreshToken", s["refreshToken"])
                save_tokens(s); print("refresh OK - already logged in, session valid."); return
            print(f"refresh renewed token but session check -> {chk.get('code')} {chk.get('description')}; full login...")
    pw = getpass.getpass("Password (hidden, never printed): ")
    dev = DEFAULT_DEV
    body = {"account": email, "password": pw, "agreement": [1, 2], "deviceId": dev, "appType": "0",
            "country": region, "accountId": None, "uid": None, "smsCode": None, "pushToken": "", "loginEmail": None}
    r = call("POST", API + "userAuth/loginAccount", body, region, dev=dev)
    print(f"[1] loginAccount -> {r.get('code')} {r.get('description')}")
    data = r.get("data") or {}
    if r.get("code") == "309702":
        r2 = call("POST", API + "userAuth/getSMSCode", {"type": "17", "email": email, "uid": None, "accountId": None}, region, dev=dev)
        print(f"[2] getSMSCode -> {r2.get('code')} {r2.get('description')}")
        code = re.sub(r"\D", "", input("    Enter the emailed code: ").strip())
        r3 = call("POST", API + "userAuth/checkSMSCode", {"email": email, "smsCode": code, "type": "17"}, region, dev=dev)
        print(f"[3] checkSMSCode -> {r3.get('code')} {r3.get('description')}")
        body["verifyCode"] = code
        r = call("POST", API + "userAuth/loginAccount", body, region, dev=dev)
        print(f"[4] loginAccount+verifyCode -> {r.get('code')} {r.get('description')}")
        data = r.get("data") or {}
    at = data.get("accessToken") if isinstance(data, dict) else None
    if not at:
        sys.exit("LOGIN FAILED.")
    save_tokens({"accessToken": at, "refreshToken": data.get("refreshToken"), "gwId": data.get("gwId"),
                 "deviceId": dev, "region": region})
    print(f"LOGIN OK (saved to {os.path.basename(TOKFILE)}).")


def cmd_vin(args):
    at, region, dev = session(refresh=False)
    vin, _ = _vin(at, region, dev)
    print(vin or "")


def cmd_whoami(args):
    at, region, dev = session()
    r = call("GET", API + "user/getUserBaseInfo", None, region, access_token=at, dev=dev)
    print(f"getUserBaseInfo -> {r.get('code')} {r.get('description')}")
    print(json.dumps(r.get("data"), indent=2)[:800])


def cmd_status(args):
    at, region, dev = session()
    vin, v = _vin(at, region, dev)
    print(f"vin: {str(vin)[:10]}...  ({(v or {}).get('appShowSeriesName') or (v or {}).get('modelName')})")
    if not vin:
        return
    r = call("GET", API + f"vehicle/getLastStatus?vin={vin}&seqNo=", None, region, access_token=at, dev=dev)
    print(f"getLastStatus -> {r.get('code')} {r.get('description')}")
    items = ((r.get("data") or {}).get("items")) or []
    interesting = {"2013021": "SOC%", "2011501": "range_km", "2041142": "charging", "2042082": "plug_in", "2013022": "charge_time_min"}
    for it in items:
        if it.get("code") in interesting:
            print(f"   {interesting[it['code']]:16s} = {it.get('value')} {it.get('unit') or ''}")


def cmd_get(args):
    at, region, dev = session(refresh=not args.no_refresh)
    r = call("GET", API + args.path, None, region, access_token=at, dev=dev)
    print(f"GET {args.path}\n -> {r.get('code')} {r.get('description')}")
    print(json.dumps(r, indent=2)[:1500])


def cmd_post(args):
    at, region, dev = session(refresh=not args.no_refresh)
    if args.file:
        body = json.load(open(args.file))
    elif args.json:
        body = json.loads(args.json)
    else:
        sys.exit("post needs --json '<body>' or --file body.json")
    r = call("POST", API + args.path, body, region, access_token=at, dev=dev)
    print(f"POST {args.path}\n body: {json.dumps(body)[:400]}\n -> {r.get('code')} {r.get('description')}")
    print(json.dumps(r, indent=2)[:1500])


def cmd_climate(args):
    """Validate a KNOWN command end-to-end: turn A/C on/off (0x04). Verify on your
    phone (primary account). PIN is MD5(pin) lowercase hex, same as the add-on."""
    at, region, dev = session()
    vin, _ = _vin(at, region, dev)
    if not vin:
        sys.exit("no vin")

    def ac_now():
        rv = call("GET", API + f"vehicle/getLastStatus?vin={vin}&seqNo=", None, region, access_token=at, dev=dev)
        return next((it.get("value") for it in ((rv.get("data") or {}).get("items") or []) if it.get("code") == "2202001"), "?")

    on = args.state == "on"
    want = "1" if on else "0"
    before = ac_now()
    print(f"A/C (2202001) BEFORE = {before}   (target {want})")
    if before == want:
        print("  already in target state -> this run can't prove causation. Set the opposite first (phone UNTOUCHED).")
    pin = os.environ.get("GWM_PIN") or getpass.getpass("6-digit control PIN (hidden): ")
    md5 = hashlib.md5(pin.encode("ascii")).hexdigest().lower()
    if args.precheck:
        rc = call("POST", API + "userAuth/checkSecurityPassword", {"securityPassword": md5, "type": "2"}, region, access_token=at, dev=dev)
        print(f"[checkSecurityPassword] -> {rc.get('code')} {rc.get('description')}")
    temp, minutes = str(args.temp), str(args.minutes)
    if on:
        r0 = call("POST", API + "vehicle/modifyVehicleRemoteCtlInfo",
                  {"airConditionerTemperature": temp, "airConditionerTime": minutes, "vin": vin},
                  region, access_token=at, dev=dev)
        print(f"[modify] -> {r0.get('code')} {r0.get('description')}")
    seq = uuid.uuid4().hex + "1234"
    body = {"instructions": {"0x04": {"airConditioner": {"operationTime": minutes,
            "switchOrder": "1" if on else "0", "temperature": temp}}},
            "remoteType": "0", "securityPassword": md5, "seqNo": seq, "type": 2, "vin": vin}
    r = call("POST", API + "vehicle/T5/sendCmd", body, region, access_token=at, dev=dev)
    print(f"[sendCmd A/C {'ON' if on else 'OFF'}] -> {r.get('code')} {r.get('description')}  (seqNo {seq[:10]}..)")
    if r.get("code") != "000000":
        print(f"  -> command not accepted: {json.dumps(r)[:200]}")
        return
    print("  KEEP THE PHONE UNTOUCHED. Polling 2202001 up to 90s (early-exit on flip):")
    for i in range(18):
        time.sleep(5)
        ac = ac_now()
        print(f"   +{(i+1)*5:3d}s  2202001 = {ac}")
        if ac == want:
            print(f"  >>> flipped {before}->{ac} after ~{(i+1)*5}s with phone untouched = OUR command caused it.")
            return
    print(f"  no flip within 90s (still {ac_now()}). Inconclusive/latency/unreliable.")


def cmd_door(args):
    """Lock/unlock the doors (0x05). 2208001: 0=locked, 1=unlocked.
    Use --no-precheck to confirm the checkSecurityPassword requirement (should no-op)."""
    at, region, dev = session()
    vin, _ = _vin(at, region, dev)
    if not vin:
        sys.exit("no vin")

    def lock_now():
        rv = call("GET", API + f"vehicle/getLastStatus?vin={vin}&seqNo=", None, region, access_token=at, dev=dev)
        return next((it.get("value") for it in ((rv.get("data") or {}).get("items") or []) if it.get("code") == "2208001"), "?")

    lock = args.state == "lock"
    want = "0" if lock else "1"
    before = lock_now()
    print(f"Lock (2208001) BEFORE = {before}   (target {want}; 0=locked,1=unlocked)")
    pin = os.environ.get("GWM_PIN") or getpass.getpass("6-digit control PIN (hidden): ")
    md5 = hashlib.md5(pin.encode("ascii")).hexdigest().lower()
    if not args.no_precheck:
        rc = call("POST", API + "userAuth/checkSecurityPassword", {"securityPassword": md5, "type": "2"}, region, access_token=at, dev=dev)
        print(f"[checkSecurityPassword] -> {rc.get('code')} {rc.get('description')}")
    else:
        print("[checkSecurityPassword] SKIPPED (--no-precheck): expect no actuation")
    seq = uuid.uuid4().hex + "1234"
    body = {"instructions": {"0x05": {"operationTime": "0", "switchOrder": "2" if lock else "1"}},
            "remoteType": "0", "securityPassword": md5, "seqNo": seq, "type": 2, "vin": vin}
    r = call("POST", API + "vehicle/T5/sendCmd", body, region, access_token=at, dev=dev)
    print(f"[sendCmd {'LOCK' if lock else 'UNLOCK'}] -> {r.get('code')} {r.get('description')}  (seqNo {seq[:10]}..)")
    if r.get("code") != "000000":
        print(f"  -> not accepted: {json.dumps(r)[:200]}")
        return
    print("  polling 2208001 up to 90s (early-exit on flip):")
    for i in range(18):
        time.sleep(5)
        now = lock_now()
        print(f"   +{(i+1)*5:3d}s  2208001 = {now}")
        if now == want:
            print(f"  >>> flipped {before}->{now} after ~{(i+1)*5}s = command actuated.")
            return
    print(f"  no flip within 90s (still {lock_now()}).")


def cmd_sigtest(args):
    """Try several GET query-signing canonicalizations against a real endpoint that
    only fails on signing (a perfect oracle). Whichever returns 000000 IS the rule."""
    at, region, dev = session(refresh=False)
    ep, q = args.ep, args.query
    abspath = API + ep
    pairs = [(p.split("=", 1) + [""])[:2] for p in q.split("&") if p]
    nonempty = [(k, v) for k, v in pairs if v != ""]
    variants = {
        "orig_nonempty":    [f"{k}={v}" for k, v in nonempty],
        "sorted_kv":        sorted(f"{k}={v}" for k, v in nonempty),
        "sorted_key":       [f"{k}={v}" for k, v in sorted(nonempty, key=lambda x: x[0])],
        "orig_with_empty":  [f"{k}={v}" for k, v in pairs],
        "sorted_key_empty": [f"{k}={v}" for k, v in sorted(pairs, key=lambda x: x[0])],
        "enc_sorted_kv":    sorted(f"{k}={quote_plus(v)}" for k, v in nonempty),
        "lc_concat":        ["".join(f"{k.lower()}={v}" for k, v in sorted(nonempty, key=lambda x: f"{x[0]}={x[1]}"))],
        "path_only":        [],
    }
    for name, plist in variants.items():
        params = "".join(plist) if name == "lc_concat" else "&".join(plist)
        url = abspath + ("?" + "&".join(f"{k}={v}" for k, v in nonempty) if nonempty else "")
        ts = str(int(time.time() * 1000)); nonce = hashlib.md5((name + str(time.time_ns())).encode()).hexdigest()[:16]
        auth = f"{PREFIX}-auth-appkey:{APP_KEY}{PREFIX}-auth-nonce:{nonce}{PREFIX}-auth-timestamp:{ts}"
        raw = re.sub(r"\s*|\t|\r|\n", "", "GET" + abspath + auth + params + APP_SEC)
        sg = hashlib.sha256(quote_plus(raw, safe="").encode()).hexdigest()
        h = {"Accept": "application/json", "Content-Type": "application/json; charset=UTF-8",
             f"{PREFIX}-auth-appkey": APP_KEY, f"{PREFIX}-auth-timestamp": ts,
             f"{PREFIX}-auth-sign": sg, f"{PREFIX}-auth-nonce": nonce, "accessToken": at,
             "rs": "2", "appId": "1", "brand": "1", "terminal": "GW_APP_Haval", "enterpriseId": "CC01",
             "systemType": "1", "cVer": "1.0.0", "channel": "APP", "language": "en_US",
             "regionCode": region, "country": region, "deviceId": dev, "iccid": dev,
             "User-Agent": "Dart/3.3 (dart:io)"}
        try:
            t = urlopen(Request(BASE + url, headers=h, method="GET"), timeout=25).read().decode("utf-8", "replace")
        except HTTPError as e:
            t = e.read().decode("utf-8", "replace")
        except Exception as e:
            t = json.dumps({"code": "_ERR", "description": str(e)})
        try:
            r = json.loads(t)
        except Exception:
            r = {"code": "_RAW", "description": t[:80]}
        flag = "  <<< WORKS" if r.get("code") == "000000" else ""
        print(f"  {name:18s} sign='{params[:46]}' -> {r.get('code')} {r.get('description')}{flag}")


def cmd_checkpin(args):
    """Validate the account's 6-digit control PIN (non-actuating). PIN via getpass,
    never printed/stored. 000000 => the PIN is correct and usable."""
    at, region, dev = session()
    pin = os.environ.get("GWM_PIN") or getpass.getpass("6-digit control PIN (hidden): ")
    md5 = hashlib.md5(pin.encode("ascii")).hexdigest().lower()
    r = call("POST", API + "userAuth/checkSecurityPassword", {"securityPassword": md5, "type": "2"},
             region, access_token=at, dev=dev)
    print(f"[checkSecurityPassword] -> {r.get('code')} {r.get('description')}")
    print("  PIN correct and accepted." if r.get("code") == "000000" else f"  full: {json.dumps(r)[:300]}")


def _ascii(s):
    return str(s).encode("ascii", "replace").decode("ascii")


def cmd_cmdresult(args):
    """Send a REAL command (A/C on) and read its result via getRemoteCtrlResultT5 WITH the
    vin header. Proves the vin header returns the real command status for a real seqNo
    (not the bogus-seqNo 250505). PIN via getpass, never printed/stored."""
    at, region, dev = session()
    vin, _ = _vin(at, region, dev)
    if not vin:
        sys.exit("no vin")
    pin = os.environ.get("GWM_PIN") or getpass.getpass("6-digit control PIN (hidden): ")
    md5 = hashlib.md5(pin.encode("ascii")).hexdigest().lower()
    call("POST", API + "vehicle/modifyVehicleRemoteCtlInfo",
         {"airConditionerTemperature": "22", "airConditionerTime": "10", "vin": vin},
         region, access_token=at, dev=dev)
    seq = uuid.uuid4().hex + "1234"
    body = {"instructions": {"0x04": {"airConditioner": {"operationTime": "10", "switchOrder": "1", "temperature": "22"}}},
            "remoteType": "0", "securityPassword": md5, "seqNo": seq, "type": 2, "vin": vin}
    r = call("POST", API + "vehicle/T5/sendCmd", body, region, access_token=at, dev=dev)
    print(f"[sendCmd A/C ON] -> {r.get('code')} {_ascii(r.get('description'))}  seqNo={seq[:12]}..")
    if r.get("code") != "000000":
        print("  not accepted; stop.")
        return
    print("  polling getRemoteCtrlResultT5 WITH vin header up to 60s:")
    for i in range(12):
        time.sleep(5)
        rr = call("GET", API + f"vehicle/getRemoteCtrlResultT5?seqNo={seq}", None, region,
                  access_token=at, dev=dev, extra_headers={"vin": vin})
        print(f"   +{(i+1)*5:3d}s -> {rr.get('code')} {_ascii(rr.get('description'))}  | {_ascii(json.dumps(rr, ensure_ascii=True)[:180])}")
        if rr.get("code") == "000000":
            print("  >>> real result via the vin header = confirmed end-to-end.")
            return
    print("  (done polling)")


def cmd_cmdprobe(args):
    at, region, dev = session()
    vin, _ = _vin(at, region, dev)
    print(f"vin {str(vin)[:10]}...  region {region}")
    print("\nPROBE (read-only): getRemoteCtrlResultT5 with a bogus seqNo")
    bogus = "0" * 32 + "1234"
    r = call("GET", API + f"vehicle/getRemoteCtrlResultT5?seqNo={bogus}", None, region, access_token=at, dev=dev,
             extra_headers={"vin": vin} if vin else None)
    print(f" -> {r.get('code')} {r.get('description')}")
    print(f" full: {json.dumps(r)[:400]}")


V2 = "/app-api/api/v2.0/"   # the app uses v2.0 for the PIN-set flow (getVerifyCode / updateSecurityPassword)


def cmd_setpin(args):
    """Set/replace the 6-digit security (control) PIN via the app's own flow:
      step 1 (no --code): POST v2.0 userAuth/getVerifyCode {account, accountType:"2", type:"5"}
      step 2 (--code C):  POST v1.0 userAuth/updateSecurityPassword {securityPasswordNew: md5(pin), verifyCode: C, ...}
    The NEW PIN is read via getpass and never printed or stored."""
    email = args.email or DEFAULT_EMAIL
    if not email:
        sys.exit("set-pin requires --email <account e-mail>")
    email = email.strip()
    at, region, dev = session()
    who = call("GET", API + "user/getUserBaseInfo", None, region, access_token=at, dev=dev)
    acct = (who.get("data") or {}).get("account")
    print(f"[auth] getUserBaseInfo -> {who.get('code')} {who.get('description')}  account={acct}")
    if who.get("code") != "000000":
        sys.exit("Not authenticated (or session held elsewhere). Run `login` first.")
    if not args.code:
        r = call("POST", V2 + "userAuth/getVerifyCode",
                 {"account": email, "accountType": "2", "type": "5"}, region, access_token=at, dev=dev)
        print(f"[getVerifyCode] -> {r.get('code')} {r.get('description')}")
        if r.get("code") != "000000":
            print("  Code NOT sent (e.g. 302000 'System busy' = GWM-side, retry later).")
        else:
            print(f"  Code sent to {email}. Then run:  python gwm_au.py set-pin --email {email} --code <CODE>")
        return
    # step 2: PIN via getpass, never printed/stored
    newpin = getpass.getpass("NEW 6-digit PIN (hidden, never printed): ")
    if not (newpin.isdigit() and len(newpin) == 6):
        sys.exit("PIN must be exactly 6 digits.")
    if getpass.getpass("confirm NEW PIN: ") != newpin:
        sys.exit("PIN mismatch.")
    md5 = hashlib.md5(newpin.encode("ascii")).hexdigest().lower()
    code = re.sub(r"\D", "", args.code)
    body = {"securityPasswordNew": md5, "verifyCode": code,
            "account": email, "accountType": "2", "type": "5"}
    r2 = call("POST", API + "userAuth/updateSecurityPassword", body, region, access_token=at, dev=dev)
    print(f"[updateSecurityPassword] -> {r2.get('code')} {r2.get('description')}")
    print(json.dumps(r2, indent=2)[:600])


def main():
    p = argparse.ArgumentParser(description="GWM ANZ (aus) API CLI - AU/NZ only, R&D tool")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("login"); sp.add_argument("--email"); sp.add_argument("--region"); sp.set_defaults(fn=cmd_login)
    sub.add_parser("whoami").set_defaults(fn=cmd_whoami)
    sub.add_parser("vin").set_defaults(fn=cmd_vin)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sp = sub.add_parser("get"); sp.add_argument("path"); sp.add_argument("--no-refresh", action="store_true"); sp.set_defaults(fn=cmd_get)
    sp = sub.add_parser("post"); sp.add_argument("path"); sp.add_argument("--json"); sp.add_argument("--file"); sp.add_argument("--no-refresh", action="store_true"); sp.set_defaults(fn=cmd_post)
    sp = sub.add_parser("climate"); sp.add_argument("state", choices=["on", "off"]); sp.add_argument("--temp", type=int, default=22); sp.add_argument("--minutes", type=int, default=30); sp.add_argument("--precheck", action="store_true"); sp.set_defaults(fn=cmd_climate)
    sp = sub.add_parser("door"); sp.add_argument("state", choices=["lock", "unlock"]); sp.add_argument("--no-precheck", action="store_true"); sp.set_defaults(fn=cmd_door)
    sp = sub.add_parser("sigtest"); sp.add_argument("ep"); sp.add_argument("query"); sp.set_defaults(fn=cmd_sigtest)
    sub.add_parser("cmd-probe").set_defaults(fn=cmd_cmdprobe)
    sub.add_parser("cmdresult").set_defaults(fn=cmd_cmdresult)
    sub.add_parser("checkpin").set_defaults(fn=cmd_checkpin)
    sp = sub.add_parser("set-pin"); sp.add_argument("--email"); sp.add_argument("--code"); sp.set_defaults(fn=cmd_setpin)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
