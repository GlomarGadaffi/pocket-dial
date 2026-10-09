# Dashboard HTTPS through a reverse proxy

You put an nginx reverse proxy in front of the board's dashboard. The proxy terminates TLS with a
certificate from your site CA and forwards plain HTTP to the board on the LAN. The board does not change.
This is option (c) in the #179 design: documentation only, no firmware.

Written from the code at `main` 760f6928. Nothing here has been run on a board. Section 9 lists what is
**UNVERIFIED**. Citations: `HS` = `src/Helpers/HttpServer.cpp`, `HH` = `HttpServer.hpp`, `AA` =
`AdminAuth.hpp`, `AC` = `AdminAuth.cpp` (all under `src/Helpers/`, at 760f6928). `D` =
`docs/design/https-dashboard.md` on branch `docs/179-https-design` at 6fd51333.

## 1. Topology

```
browser ------HTTPS------> nginx (dash.example.com) ------HTTP------> board :80
phones, Prometheus --------------------HTTP---------------------------> board :80   (never via the proxy)
```

- The board stays on plain HTTP, port 80, and stays reachable on its own address (D:127-134). The
  proxy-to-board hop is cleartext (D:145): put the proxy on the board's segment or on a link you trust.
- This is for wired builds at sites with an internal CA (D:183-186). On the SoftAP, use WPA2
  (`docs/THREAT_MODEL.md` section 6).
- Why nginx: the recipe needs a rate limiter and a conditional `Origin` rewrite, and stock nginx has both
  (`limit_req`, `limit_conn`, `map`). Caddy is not covered.

## 2. The config

Needs nginx 1.18 or later. Put it in `conf.d`, which loads inside `http {}`. Replace `192.168.1.50` with the
board's address (use a DHCP reservation or a static address) and `dash.example.com` with your name.

```nginx
# Rewrite only our own public origin into one the board accepts. No Origin stays
# no Origin. Any other Origin passes through unchanged and the board answers 403.
map $http_origin $pd_origin {
    default                     $http_origin;
    "https://dash.example.com"  "http://pocketdial.local";   # add :port here if not 443
}

# Count login requests only. An empty key is not counted.
map $uri $pd_login_key {
    default           "";
    /api/admin/login  $binary_remote_addr;
}
limit_req_zone  $pd_login_key zone=pd_login:1m rate=6r/m;
limit_conn_zone $server_name  zone=pd_conn:1m;

server {
    listen 443 ssl;
    server_name dash.example.com;

    ssl_certificate     /etc/ssl/site/dash.example.com.crt;   # issued by your site CA
    ssl_certificate_key /etc/ssl/site/dash.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Keep every proxy_set_header here. One proxy_set_header inside a location
    # silently drops the ones inherited from the server block.
    proxy_set_header Host   pocketdial.local;
    proxy_set_header Origin $pd_origin;         # empty value means the header is not sent

    client_max_body_size 16k;    # the board's own cap (HS:825); firmware/MoH uploads go direct
    limit_conn pd_conn 3;        # the board allows 3 of its 4 slots per source (HH:110)
    limit_conn_status 503;       # same code the board gives when busy

    # Plain HTTP only. See section 5.
    location ^~ /config/ { return 404; }
    location = /metrics  { return 404; }

    location / {
        limit_req zone=pd_login burst=3 nodelay;   # 4 quick login requests, then 1 per 10 s
        limit_req_status 429;
        proxy_pass http://192.168.1.50:80;   # keep request buffering on: the board reads a body only
    }                                        # via Content-Length, no chunked support (HS:801-876)
}
```

## 3. What the proxy breaks, and the fix

### Host and Origin

The board checks both headers, and the proxy's public name fails both.

- Saves, login and logout. `isSameOrigin` allows a request with no `Origin` (HS:4175). If an `Origin` is
  present, `Host` must be the device IP, `192.168.4.1`, `pocketdial.local`, `localhost` or `127.0.0.1` (port
  ignored), and the `Origin` host must equal it (HS:4195-4203). Browsers send `Origin` on POST, PUT and
  DELETE, so each returns 403 `cross-origin request rejected` with `Host: dash.example.com`, login included
  (HS:1492-1497).
- Page loads. On device builds, a GET whose `Host` contains none of `192.168.4.1`, `localhost`,
  `pocketdial` or the board IP gets a 302 to `http://192.168.4.1/` (HS:893-907, `ESP_PLATFORM` only). So
  `GET /` bounces the browser off the proxy.

**The fix is to rewrite, not preserve.** The proxy sends `Host: pocketdial.local`, which passes both checks
(HS:898, 4199). The board only compares the string, so mDNS does not need to work. The proxy rewrites an
`Origin` equal to your public origin to `http://pocketdial.local`, and nothing else. Do not overwrite `Origin`
for every request: that makes the board's origin check a no-op for everything behind the proxy.

The board has no trusted-proxy handling. It keeps five request headers: `Origin`, `Host`, `Cookie`,
`X-CSRF`, `User-Agent` (HS:1580-1590). It never reads `X-Forwarded-For`, `Forwarded` or `X-Real-IP`, so it
cannot learn the real client address.

### The login lockout is shared

The lockout key is (TCP peer address, account) (HS:657-676, 884, 5408-5413; AC:1383). Behind the proxy the
peer is always the proxy. Five consecutive failed logins from anyone behind it lock every proxied login for
that account for 60 s. Each further lockout doubles the time, up to about 16 min, and only a correct login
resets the count (AA:60-61, 71-73; `docs/ETH_SMOKE.md:286`). The 20-failure backstop per account is shared by
everyone, direct clients included (AA:82, AC:1386-1390), so a guesser behind the proxy can also lock the
direct login.

The `limit_req` in section 2 bounds each client's guess rate. It does **not** isolate the lockout: one client
can still lock out every proxied user (D:137-141).

### The connection cap and header size

The board holds 4 connections, at most 3 per source address (HH:99, 110; HS:467-476). The proxy is one
source, so it gets 3, and every open dashboard tab shares them. The board's own cap keeps the fourth slot
free for a direct client; `limit_conn 3` only makes nginx refuse first.

The board reads request headers from one 4095-byte `recv` and has no loop that reads on until the header
terminator (HS:697-714, 834-838). Cookies from a parent domain (SSO, analytics) that the proxy forwards can
push `Cookie` or `X-CSRF` past that cut, which shows as 401 or 403. Use a dedicated name with no
parent-domain cookies. This is from the code only (UNVERIFIED on a board).

## 4. Cookie, and what HTTPS buys you

`pd_session` is set as `HttpOnly; Path=/; SameSite=Strict` with no `Secure` flag (HS:5449-5450). The board
does not set `Secure`, and this recipe does not add it at the proxy. HTTP stays reachable and the same session
token is valid on every path to the board, so a token seen on any plain-HTTP path (a direct client, or the
proxy-to-board hop) can be replayed at the proxy. HTTPS here protects the browser-to-proxy leg against passive
sniffing, and nothing stronger (D:38-41). Neither the board (HS:1619-1621) nor this recipe sends HSTS.

## 5. Leave these on plain HTTP

| Path | Used by | Reason |
|---|---|---|
| `/config/<file>` | Phone auto-provisioning (HS:915, 3123) | Profiles point at `http://<board>` (HS:3268). Zero-touch and Cisco SPA lookup identify the phone by the ARP entry of the TCP peer (HS:3235-3242, 3278-3290), which would be the proxy. |
| `/metrics` | Prometheus | Ungated by design (HS:944). |
| Captive redirect | SoftAP clients | Device builds only (HS:893-907). |

The config leaves them alone: the proxy has its own name, the two `return 404` locations stop the TLS name
serving provisioning or metrics, and the `Host` rewrite stops the captive redirect firing on proxied
requests. Point phones, DHCP option 66 and your scraper at `http://<board>`, never at the proxy name. Do not
firewall the board's port 80 down to the proxy alone: that cuts phones, the scraper and your break-glass
admin host (section 6). If you restrict port 80, allow those three. That rule is yours to write, untested here.

## 6. Rule 5

Rule 5, as the repo states it, is that nothing may delay or refuse an emergency call (D:149-150). The proxy
is a separate host and never sees SIP or RTP. The dashboard does host the E911 form (`PUT /api/e911-config`, HS:1232), so keep that
form reachable without the proxy:

1. Leave the board's port 80 open to at least one admin host. A proxy outage or an expired certificate must
   not put TLS health in the emergency-config path (D:154-157).
2. Do not add an HTTP-to-HTTPS redirect or HSTS for the board's address (D:156-157).

## 7. Not supported

- Device-side TLS: no certificate generation on the board, no `https_enabled`, no listener on 443. Option (b)
  in the design is not approved, and nothing here prepares for it.
- HTTPS-only: HTTP is not unbound or redirected (D:61-62), and the cookie is not `Secure`.
- Per-user lockout, trusted-proxy handling or `X-Forwarded-For` (section 3).
- Proxying provisioning, `/metrics` or the captive redirect (section 5).
- Firmware and MoH upload through the proxy: the 16k limit blocks both (HS:731-733, 825). Upload directly.
- More than one name, or a sub-path: serve the dashboard from the root of one dedicated name.

## 8. Verify by hand

No call, no ring, no hardware action beyond reading the dashboard. The shell commands make no login attempt.
Step 5 sends a POST that the board should refuse; if it were accepted it would be a logout with no session,
a no-op. Step 8 signs in once with your real credential. Never test with a wrong password: failed logins
count toward the shared lockout.

```sh
BOARD=192.168.1.50; NAME=dash.example.com; CA=/path/to/site-ca.pem
code() { curl -s -o /dev/null -w '%{http_code}\n' "$@"; }

# 1. Config loads.                         expect: "syntax is ok", "test is successful"
sudo nginx -t && sudo systemctl reload nginx

# 2. The board is unchanged.               expect: 200, 200
code http://$BOARD/api/status; code http://$BOARD/metrics

# 3. Captive redirect does not fire.       expect: "200 " (empty URL). "302 http://192.168.4.1/" = Host not rewritten
curl --cacert $CA -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://$NAME/

# 4. Origin check. Own origin passes (401: no session, HS:1063-1077; 403 = rewrite failed). Foreign is refused.
#                                          expect: 401, 403
code --cacert $CA -H "Origin: https://$NAME" https://$NAME/api/cdr
code --cacert $CA -H 'Origin: https://evil.example' https://$NAME/api/cdr

# 5. Without the rewrite the board says no (the failure this recipe fixes).   expect: 403
code -X POST -H "Host: $NAME" -H "Origin: https://$NAME" http://$BOARD/api/admin/logout

# 6. Plain-HTTP paths are not proxied.     expect: 404, 404, then 200
code --cacert $CA https://$NAME/metrics; code --cacert $CA https://$NAME/config/000000000000.cfg
code http://$BOARD/config/000000000000.cfg      # Polycom master file, no registry lookup (HS:3220-3225)

# 7. Login limiter.                        expect: four board answers, then 429 (UNVERIFIED which code)
#    These are GETs, which the board does not count. Wait a minute before signing in again.
for i in 1 2 3 4 5 6 7 8; do code --cacert $CA https://$NAME/api/admin/login; done
```

8. In a browser, open `https://$NAME/`. The certificate should chain to your site CA with no warning. Sign in,
   then open DevTools, Application, Cookies: `pd_session` shows HttpOnly and SameSite Strict, and no Secure.
   The dashboard should load and poll with no console errors.

## 9. UNVERIFIED

- Nothing was run on a board. Every board behavior above comes from reading the code at 760f6928. The
  captive redirect is `ESP_PLATFORM` only (HS:893), so no host test covers it.
- The nginx config has not been through `nginx -t` or run; nginx was not available. The directive behavior
  (an empty header value is not sent, an empty `limit_req` key is not counted, a variable as a `map` default)
  is from the nginx documentation, not from running it.
- A full browser session through the proxy (login, CSRF-bearing saves, status polling) is untried.
- The rate and burst numbers are examples, not tuned. Several tabs against the 3-connection cap is untried.
- Step 7: the status the board returns to a GET on the login route. Upload through a raised
  `client_max_body_size`. Neither was tried.
