# tools/

Developer / R&D tooling. **Not part of the add-on runtime.**

## `gwm_au.py` — GWM ANZ (AU/NZ) API probe

A single-file Python CLI that speaks the AU/NZ (`aus` region) `bt-auth` API directly — login,
status, remote commands, and the result poll — written while reverse-engineering the ANZ
backend (it's what cracked the GET signing rule and confirmed the `getRemoteCtrlResultT5` `vin`
header). **AU/NZ only** — EU authenticates with a client certificate, not `bt-auth`.

Protocol reference: the *AU/NZ developer notes* under `addons/gwm_ora/docs/` (see
moryoav/ha-gwm_ora#10).

```
python tools/gwm_au.py login --email you@example.com   # prompts for password + emailed code
python tools/gwm_au.py status                          # SoC, range, charging, plug
python tools/gwm_au.py checkpin                         # validate the 6-digit control PIN
```

Notes:
- Tokens are cached in `gwm_token_v2.json` beside the script (git-ignored). Passwords/PINs are
  read via `getpass` and never stored.
- GWM allows **one active session per account** — a login here bumps the phone/app. Use a
  dedicated account, and set `--region` to the account's **registration** country (e.g. `NZ`).
- `APP_KEY` / `APP_SEC` in the script are the GWM app's public constants (already in the add-on
  source), not secrets.
