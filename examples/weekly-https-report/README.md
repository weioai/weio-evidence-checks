# Weekly client-site HTTPS and certificate report (n8n)

Every Monday at 08:00 this workflow checks each of your client domains, both the bare address and `www.`, the way a visitor's browser would. It returns one row per address that needs attention:
- the browser shows a full-page privacy warning;
- the browser labels the site "Not secure";
- the certificate ends within 21 days.

Healthy addresses are listed after the problems. Connect the last node to email, Slack or a sheet to receive the report.

The check is Weio's HTTPS check, reached through RapidAPI with your own RapidAPI key. Weio is an AI-operated company.

## What you need
- n8n, self-hosted or cloud, recent enough to have the Schedule Trigger, Split Out and HTTP Request v4 nodes.
- A RapidAPI account subscribed to **Website Facts and HTTPS Check** (publisher `weioinc`).
  - The plans listed on 2026-10-20: **BASIC**, free, 100 requests a month; **PRO**, $12 a month, 1,000 requests a month. Both are hard limits.
  - One request checks one domain, covering both its bare and `www.` addresses.
  - Check the current plans on RapidAPI before subscribing. RapidAPI handles billing and the key.

Size it so a whole billing month fits inside your plan. Each full run uses one request per domain.

    domains (D) × (S + T + R) ≤ requests left this month

- **S**: scheduled runs in a month: up to **5** for a weekly schedule, **31** for a daily one.
- **T**: the one **Test workflow** run you make while setting it up (at least 1).
- **R**: extra full runs you choose to make by hand. Nothing retries automatically.
- Subtract any other calls you make with the same key.

So D is at most the requests left divided by (S + T + R), rounded down. With S + T + R = 7 for weekly and 33 for daily:

| Schedule (S + T + R) | BASIC (100/month) | PRO (1,000/month) |
|---|---|---|
| Weekly (5 + 1 + 1 = 7) | up to 14 domains (98 requests, 2 spare) | up to 142 domains (994 requests, 6 spare) |
| Daily (31 + 1 + 1 = 33) | up to 3 domains (99 requests, 1 spare) | up to 30 domains (990 requests, 10 spare) |

If you will make more runs by hand, use fewer domains or a less frequent schedule. The plan limits above are as listed on 2026-10-20; check the current ones on RapidAPI.

**Status: prototype.** The report logic has been tested offline only. A real n8n import and a real RapidAPI call are UNTESTED by Weio. Run it once yourself and check the output before relying on it.

## Set up
1. In n8n: **Workflow menu > Import from File**, then pick `weekly-https-report.json`.
2. Open **Check HTTPS (RapidAPI)**. Under Credential, create a **Header Auth** credential:
   - Name: `x-rapidapi-key`
   - Value: your RapidAPI key.

   The key stays in n8n's credential store, not in the workflow file.
3. Open **Client domains (edit me)** and replace `["example.com", "example.org"]` with your clients' domains.
4. Run it once with **Test workflow**, then activate it.

The HTTP node is set to send one request every 2 seconds. Check your plan's current rate limit before you add many domains; nothing retries a failed request automatically. "Never error" is on, so one bad domain doesn't stop the rest; it appears as a `CHECK FAILED` row.

## What each row means

| Field | Meaning |
|---|---|
| `status` | `ACTION NEEDED`, `OK` or `CHECK FAILED` |
| `browser` | `ok`, `not_secure` (plain http: the address bar says "Not secure") or `interstitial` (a full-page "Your connection is not private" warning) |
| `cause` | `ok`, `expired`, `www_missing` (the certificate covers only the other of bare/www), `wrong_cert`, `self_signed`, `no_https`, `platform` (only the site builder can fix it) or `unknown` |
| `certificate_valid_until`, `days_left` | From the certificate the browser is served |
| `explanation` | One plain-English sentence on what the visitor sees and what fixes it |

## Limits, plainly
- It reports what a browser shows for the public address: redirects, the certificate and the warning. It is not a security audit and doesn't scan anything else.
- It only checks public domain names. IP addresses and private hosts are refused.
- The 21-day warning is a setting at the top of the **Report rows** node (`WARN_DAYS`).

## Files
- `weekly-https-report.json`: the importable workflow.
- `report-rows.js`: the same code as the Report rows node, kept for review.
- `test-report-rows.mjs` and `TEST-OUTPUT.txt`: offline test of the report logic. The inputs are a real recorded example.com answer, a certificate ending in 10 days, and a rate-limited failure.
