#!/usr/bin/env bash
# End-to-end smoke test for the bUI panel API against a running backend.
#
# It creates an inbound, clients, keys, a remote source and demo data, and
# asserts the responses. Run it against a THROWAWAY instance: it assumes a fresh
# database, changes the admin password at the end, and leaves rows behind.
#
#   cd panel/backend
#   rm -f /tmp/bui-smoke.db*
#   BPROTO_DB="sqlite:///tmp/bui-smoke.db?mode=rwc" \
#   BPROTO_TAG_KEY=2222222222222222222222222222222222222222222222222222222222222222 \
#   BPROTO_ADMIN_PASSWORD=admin \
#   BPROTO_INTERNAL_TOKEN=devtoken \
#   BPROTO_LISTEN=127.0.0.1:8099 \
#     cargo run &
#
#   BASE=http://127.0.0.1:8099 bash ../smoke.sh
#
# Needs bash, curl, jq and python3.
set -euo pipefail
base="${BASE:-http://127.0.0.1:8080}"
admin_user="${ADMIN_USER:-admin}"
admin_pass="${ADMIN_PASS:-admin}"
internal_token="${INTERNAL_TOKEN:-devtoken}"
tag_key="${TAG_KEY:-2222222222222222222222222222222222222222222222222222222222222222}"
pass=0
fail=0

check() { # check <name> <actual> <expected>
  if [ "$2" = "$3" ]; then printf 'ok   %s\n' "$1"; pass=$((pass+1));
  else printf 'FAIL %s (got %s, want %s)\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

# --- auth ------------------------------------------------------------------
token=$(curl -sf -X POST "$base/api/auth/login" -H 'content-type: application/json' \
  -d "{\"username\":\"$admin_user\",\"password\":\"$admin_pass\"}" | jq -r .token)
[ -n "$token" ] && [ "$token" != null ] && printf 'ok   login\n' && pass=$((pass+1))
auth=(-H "authorization: Bearer $token")

check "health" "$(curl -sf "$base/api/health")" "ok"
check "me panel" "$(curl -sf "${auth[@]}" "$base/api/me" | jq -r .panel)" "bUI"
check "bad token rejected" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H 'authorization: Bearer nope' "$base/api/users")" "401"
check "no token rejected" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$base/api/users")" "401"

# --- inbound ---------------------------------------------------------------
inbound=$(curl -sf -X POST "$base/api/inbounds" "${auth[@]}" -H 'content-type: application/json' \
  -d '{"remark":"DE-Frankfurt","server":"203.0.113.10:443","donor_sni":"www.cloudflare.com","listen_port":443}')
inbound_id=$(jq -r .id <<<"$inbound")
check "inbound created" "$(jq -r '.id | type' <<<"$inbound")" "number"
check "inbound bad server rejected" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/inbounds" "${auth[@]}" \
     -H 'content-type: application/json' -d '{"remark":"x","server":"vpn.example.com:443","donor_sni":"a.com"}')" "400"

# --- client ----------------------------------------------------------------
client=$(curl -sf -X POST "$base/api/inbounds/$inbound_id/clients" "${auth[@]}" \
  -H 'content-type: application/json' \
  -d '{"username":"alice","traffic_limit_bytes":1073741824,"label":"Pixel"}')
client_id=$(jq -r .user_id <<<"$client")
sub_url=$(jq -r .sub_url <<<"$client")
check "client created" "$(jq -r '.user_id | type' <<<"$client")" "number"
check "config uri shape" "$(jq -r '.config_uri | startswith("bproto://import/")' <<<"$client")" "true"
check "qr rendered" "$(jq -r '.qr_svg | contains("<svg")' <<<"$client")" "true"
check "duplicate username rejected" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/inbounds/$inbound_id/clients" "${auth[@]}" \
     -H 'content-type: application/json' -d '{"username":"alice"}')" "409"

check "inbound rollup" "$(curl -sf "${auth[@]}" "$base/api/inbounds" | jq -r '.inbounds[0].clients')" "1"
check "client list inbound" "$(curl -sf "${auth[@]}" "$base/api/users?inbound_id=$inbound_id" | jq -r '.clients | length')" "1"
check "client has sub url" \
  "$(curl -sf "${auth[@]}" "$base/api/users/$client_id" | jq -r '.client.sub_url | startswith("http")')" "true"

# --- second key, per-key config -------------------------------------------
key2=$(curl -sf -X POST "$base/api/users/$client_id/keys" "${auth[@]}" \
  -H 'content-type: application/json' -d '{"label":"Laptop"}')
key2_id=$(jq -r .key_id <<<"$key2")
check "second key" "$(curl -sf "${auth[@]}" "$base/api/users/$client_id/keys" | jq -r '.keys | length')" "2"
check "re-issued config" \
  "$(curl -sf "${auth[@]}" "$base/api/keys/$key2_id/config" | jq -r '.config_uri | startswith("bproto://import/")')" "true"

# --- subscription ----------------------------------------------------------
check "sub base64" "$(curl -sf "$sub_url" | base64 -d | grep -c 'bproto://import/')" "2"
check "sub list" "$(curl -sf "$sub_url?format=list" | grep -c 'bproto://import/')" "2"
check "sub json" "$(curl -sf "$sub_url?format=json" | jq -r '.count')" "2"
check "sub userinfo header" \
  "$(curl -sfD- -o /dev/null "$sub_url" | grep -ci '^subscription-userinfo:')" "1"
check "sub profile-title header" \
  "$(curl -sfD- -o /dev/null "$sub_url" | grep -ci '^profile-title: base64:')" "1"
check "sub unknown id" "$(curl -s -o /dev/null -w '%{http_code}' "$base/sub/deadbeef")" "404"
check "sub list api" "$(curl -sf "${auth[@]}" "$base/api/subscriptions" | jq -r '.items | length >= 1')" "true"

# --- traffic report --------------------------------------------------------
tag=$(BPROTO_TAG_KEY="$tag_key" BPROTO_UID="$client_id" python3 -c '
import hmac, hashlib, os
key = bytes.fromhex(os.environ["BPROTO_TAG_KEY"])
tag = hmac.new(key, b"bproto-tag" + int(os.environ["BPROTO_UID"]).to_bytes(8, "big"), hashlib.sha256).digest()[:8]
print(tag.hex())')
report=$(curl -sf -X POST "$base/internal/v1/sessions/report" \
  -H "authorization: Bearer $internal_token" -H 'content-type: application/json' \
  -d "{\"server_id\":\"de1\",\"sessions\":[{\"tag\":\"$tag\",\"started_at\":$(( $(date +%s) - 30 )),\"bytes_rx\":1000000,\"bytes_tx\":2000000,\"peer_ip\":\"198.51.100.9\"}]}")
check "report accepted" "$(jq -r .accepted <<<"$report")" "1"
check "report unknown tag" \
  "$(curl -sf -X POST "$base/internal/v1/sessions/report" -H "authorization: Bearer $internal_token" \
     -H 'content-type: application/json' -d '{"sessions":[{"tag":"0000000000000000","bytes_rx":1,"bytes_tx":1}]}' | jq -r '.unknown | length')" "1"
check "report needs token" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/internal/v1/sessions/report" \
     -H 'content-type: application/json' -d '{"sessions":[]}')" "401"
check "traffic counted" \
  "$(curl -sf "${auth[@]}" "$base/api/users/$client_id" | jq -r '.client.traffic_used_bytes')" "3000000"
check "online" "$(curl -sf "${auth[@]}" "$base/api/stats/overview" | jq -r .online)" "1"
check "series buckets" "$(curl -sf "${auth[@]}" "$base/api/stats/overview" | jq -r '.series_24h | length')" "24"
check "by inbound" "$(curl -sf "${auth[@]}" "$base/api/stats/inbounds" | jq -r '.inbounds[0].online')" "1"
check "top clients" "$(curl -sf "${auth[@]}" "$base/api/stats/top" | jq -r '.clients[0].username')" "alice"
check "sessions list" "$(curl -sf "${auth[@]}" "$base/api/stats/sessions" | jq -r '.sessions[0].username')" "alice"
check "system info" "$(curl -sf "${auth[@]}" "$base/api/stats/system" | jq -r '.panel')" "bUI"

# --- remote subscription from "another bProto server" ----------------------
remote=$(curl -sf -X POST "$base/api/remote-subs" "${auth[@]}" -H 'content-type: application/json' \
  -d "{\"name\":\"lab-b\",\"url\":\"$sub_url?format=list\"}")
remote_id=$(jq -r .id <<<"$remote")
check "remote sub added" "$(jq -r .entry_count <<<"$remote")" "2"
check "remote sub entries" "$(curl -sf "${auth[@]}" "$base/api/remote-subs/$remote_id/entries" | jq -r '.entries | length')" "2"
check "remote refresh" \
  "$(curl -sf -X POST "$base/api/remote-subs/$remote_id/refresh" "${auth[@]}" | jq -r .last_status)" "ok"

# attach it to a second client: its subscription must aggregate both
client2=$(curl -sf -X POST "$base/api/inbounds/$inbound_id/clients" "${auth[@]}" \
  -H 'content-type: application/json' -d '{"username":"bob"}')
client2_id=$(jq -r .user_id <<<"$client2")
sub2=$(jq -r .sub_url <<<"$client2")
check "attach" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/users/$client2_id/remote-subs" "${auth[@]}" \
     -H 'content-type: application/json' -d "{\"remote_sub_id\":$remote_id}")" "201"
check "aggregated sub (1 own + 2 remote)" "$(curl -sf "$sub2?format=list" | grep -c 'bproto://import/')" "3"
check "aggregation counted on client" \
  "$(curl -sf "${auth[@]}" "$base/api/users/$client2_id" | jq -r '.client.remote_subs')" "1"
check "detach" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$base/api/users/$client2_id/remote-subs/$remote_id" "${auth[@]}")" "200"
check "sub back to 1" "$(curl -sf "$sub2?format=list" | grep -c 'bproto://import/')" "1"
check "bad url scheme refused" \
  "$(curl -s -X POST "$base/api/remote-subs" "${auth[@]}" -H 'content-type: application/json' \
     -d '{"url":"file:///etc/passwd"}' | jq -r '.error | length > 0')" "true"

# --- disable / revoke semantics -------------------------------------------
check "disable client" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH "$base/api/users/$client2_id" "${auth[@]}" \
     -H 'content-type: application/json' -d '{"status":"disabled"}')" "200"
check "disabled sub is 403" "$(curl -s -o /dev/null -w '%{http_code}' "$sub2")" "403"
check "delete inbound needs flag" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$base/api/inbounds/$inbound_id" "${auth[@]}")" "409"
check "reset traffic" \
  "$(curl -sf -X POST "$base/api/inbounds/$inbound_id/reset-traffic" "${auth[@]}" | jq -r '.clients_reset')" "2"

# --- demo data -------------------------------------------------------------
check "demo seed" "$(curl -sf -X POST "$base/api/stats/demo?count=10" "${auth[@]}" | jq -r .inserted)" "10"
check "demo visible" \
  "$(curl -sf "${auth[@]}" "$base/api/stats/sessions?limit=100" | jq -r '[.sessions[] | select(.server_id=="demo")] | length >= 10')" "true"
check "demo cleared" "$(curl -sf -X DELETE "$base/api/stats/demo" "${auth[@]}" | jq -r .deleted)" "10"
check "demo gone" \
  "$(curl -sf "${auth[@]}" "$base/api/stats/sessions?limit=100" | jq -r '[.sessions[] | select(.server_id=="demo")] | length')" "0"

# --- admins / password / audit --------------------------------------------
check "admins listed" "$(curl -sf "${auth[@]}" "$base/api/admins" | jq -r '.admins[0].username')" "$admin_user"
check "second admin" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/admins" "${auth[@]}" \
     -H 'content-type: application/json' -d '{"username":"ops","password":"operations-pass-1"}')" "201"
check "short password refused" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/admins" "${auth[@]}" \
     -H 'content-type: application/json' -d '{"username":"shorty","password":"123"}')" "400"
check "wrong current password" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/auth/password" "${auth[@]}" \
     -H 'content-type: application/json' -d "{\"current_password\":\"nope\",\"new_password\":\"a-long-enough-pass\"}")" "401"
check "change own password" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/auth/password" "${auth[@]}" \
     -H 'content-type: application/json' -d "{\"current_password\":\"$admin_pass\",\"new_password\":\"panel-admin-pass\"}")" "200"
check "old password dead" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/auth/login" -H 'content-type: application/json' \
     -d "{\"username\":\"$admin_user\",\"password\":\"$admin_pass\"}")" "401"
check "new password works" \
  "$(curl -s -X POST "$base/api/auth/login" -H 'content-type: application/json' \
     -d "{\"username\":\"$admin_user\",\"password\":\"panel-admin-pass\"}" | jq -r '.token | length > 0')" "true"
check "client cannot log in" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base/api/auth/login" -H 'content-type: application/json' \
     -d '{"username":"alice","password":"panel-admin-pass"}')" "401"
check "audit has entries" \
  "$(curl -sf "${auth[@]}" "$base/api/audit?limit=200" | jq -r '[.entries[] | select(.action=="change_password")] | length')" "1"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
