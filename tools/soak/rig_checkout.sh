#!/usr/bin/env bash
# tools/soak/rig_checkout.sh -- claim and release the #401 test rig (item 0.3).
#
#   rig_checkout.sh claim   --holder NAME --purpose TEXT (--minutes N | --until ISO)
#                           [--resources pd195,glolab] [--break-expired]
#   rig_checkout.sh release --holder NAME --verdict PASS|FAIL|INVALID|ABORTED|NEEDS-HUMAN
#                           [--evidence TEXT] [--note TEXT]
#   rig_checkout.sh status
#   rig_checkout.sh post    --file POST.md [--confirm]
#   rig_checkout.sh ssh     [--flash-step | --abort-path] -- PROGRAM [ARGS...]
#   rig_checkout.sh redact  < in > out
#   rig_checkout.sh scan    FILE...
#
# claim takes a lease on every resource at once (both or neither) and writes
# the discussion #428 CHECK-OUT post, with its expiry, to a file. It refuses:
#   - while any resource has a live lease (it names the holder), or an expired
#     one unless --break-expired is passed;
#   - while a human hold file <LOCK_DIR>/<resource>.hold exists (never overridden);
#   - while a command holds <LOCK_DIR>/<resource>.lock (`flock` users, e.g. a flash);
#   - when the window crosses glolab's 03:30 auto-reboot (03:25-03:45 glolab time).
# release frees the leases of that holder and ALWAYS writes the CHECK-IN post
# with the verdict, even when there was nothing left to free.
#
# Leases and glolab's reboot. On glolab /var/lock is /run/lock, a tmpfs, so a
# lease vanishes at every reboot: claim then finds no lease and says so (the
# #428 post is the social lock; read it). On a persistent PD_RIG_LOCK_DIR a lease
# written before glolab's last boot is STALE, not live: claim takes over and
# says so. The boot time is now - uptime, from /proc/uptime here, or from
# glolab's /proc/uptime through the ssh wrapper when PD_RIG_BOOT_VIA_SSH=1. When
# it cannot be read, a live lease still refuses (fail closed).
#
# Nothing here talks to GitHub except `post --confirm`. That step is separate and
# explicit, the tests never run it, and it scans the post for secrets first. gh
# reads its own token (`gh auth`): no token is ever on an argv, and the body goes
# in from the file (-F body=@file).
#
# ssh runs one allowlisted command on glolab (tools/soak/rig_policy.py holds the
# list). The target is user@IPv4 with BigDog's key, never a host name. A serial
# port is opened only by esptool in --flash-step with --after no_reset; uhubctl
# runs only with --abort-path; an argument naming 911/933/112 is refused.
#
# Environment (defaults in brackets):
#   PD_RIG_LOCK_DIR [/var/lock]  PD_RIG_POST_DIR [$HOME/rig-posts]
#   PD_RIG_RESOURCES [pd195,glolab]
#   PD_GLOLAB_TZ [America/New_York]: glolab's zone, which sets the 03:30 window
#     wherever this runs (on glolab or off it, e.g. from BigDog)
#   PD_GLOLAB [claude-agent@192.168.12.110]  PD_GLOLAB_KEY [~/.ssh/id_ed25519_bigdog]
#   PD_SECRETS_FILE [none]: literal secrets to mask and scan for, one per line
#   PD_RIG_LOG [none]: every wrapped ssh command is appended here, redacted
#   PD_RIG_DISCUSSION_ID [discussion #428's node id]
#   PD_RIG_BOOT_VIA_SSH [0]: 1 = read glolab's boot time over the ssh wrapper
#   PD_RIG_PROC_UPTIME [/proc/uptime]  PD_RIG_NOW: test hooks ("now" in epoch s)
#
# Exit status: 0 done, 1 refused, 2 usage.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
POLICY=(python3 "$HERE/rig_policy.py")
LOCK_DIR=${PD_RIG_LOCK_DIR:-/var/lock}
POST_DIR=${PD_RIG_POST_DIR:-$HOME/rig-posts}
RESOURCES=${PD_RIG_RESOURCES:-pd195,glolab}
GLOLAB=${PD_GLOLAB:-claude-agent@192.168.12.110}
KEY=${PD_GLOLAB_KEY:-$HOME/.ssh/id_ed25519_bigdog}
DISCUSSION_ID=${PD_RIG_DISCUSSION_ID:-D_kwDOSATDcc4Apfdt}
SECRETS=${PD_SECRETS_FILE:-}
TZARG=(--tz "${PD_GLOLAB_TZ:-America/New_York}")
SECARG=()
[ -n "$SECRETS" ] && SECARG=(--secrets-file "$SECRETS")

die()   { echo "rig_checkout: REFUSED: $*" >&2; exit 1; }
usage() { sed -n '2,13p' "$0" >&2; exit 2; }
now()   { if [ -n "${PD_RIG_NOW:-}" ]; then echo "$PD_RIG_NOW"; else date -u +%s; fi; }
field() { sed -n "s/^$1=//p" "$2" 2>/dev/null | head -n 1; }

boot_epoch() {   # glolab's last boot, epoch seconds; prints nothing when unknown
  local up=""
  if [ "${PD_RIG_BOOT_VIA_SSH:-0}" = 1 ]; then
    up=$(bash "$0" ssh -- cat /proc/uptime 2>/dev/null | awk 'NR==1{print $1}')
  else
    up=$(awk 'NR==1{print $1}' "${PD_RIG_PROC_UPTIME:-/proc/uptime}" 2>/dev/null)
  fi
  [[ $up =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 0
  echo $(( $(now) - ${up%%.*} ))
}

with_claims_lock() {   # serialises claim/release read-modify-write of the leases
  exec 9>"$LOCK_DIR/pd-rig-claims.lock" || die "cannot open $LOCK_DIR/pd-rig-claims.lock"
  flock -w 10 9 || die "another claim or release is in progress"
}

claim() {
  local holder="" purpose="" minutes="" until="" brk=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --holder) holder=${2:-}; shift ;;
      --purpose) purpose=${2:-}; shift ;;
      --minutes) minutes=${2:-}; shift ;;
      --until) until=${2:-}; shift ;;
      --resources) RESOURCES=${2:-}; shift ;;
      --break-expired) brk=1 ;;
      *) usage ;;
    esac
    shift
  done
  [[ $holder =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || die "--holder must be 1-40 of [A-Za-z0-9_.-]"
  [ -n "$purpose" ] || die "--purpose is required"
  local start end
  start=$(now)
  if [ -n "$minutes" ]; then
    [[ $minutes =~ ^[0-9]+$ ]] && [ "$minutes" -gt 0 ] || die "--minutes must be a positive integer"
    end=$((start + minutes * 60))
  elif [ -n "$until" ]; then
    end=$("${POLICY[@]}" epoch "$until") || exit 1
  else
    die "--minutes or --until is required (a check-out always has an expiry)"
  fi
  [ "$end" -gt "$start" ] || die "the expiry is not in the future"
  "${POLICY[@]}" window "$start" "$end" "${TZARG[@]}" || exit 1

  local r IFS_OLD=$IFS; IFS=, read -r -a res <<< "$RESOURCES"; IFS=$IFS_OLD
  [ "${#res[@]}" -gt 0 ] || die "no resources"
  for r in "${res[@]}"; do
    [[ $r =~ ^[a-z0-9_-]{1,32}$ ]] || die "bad resource name '$r'"
    [ -e "$LOCK_DIR/$r.hold" ] && die "$r has a human hold ($LOCK_DIR/$r.hold): never overridden"
  done
  with_claims_lock
  local boot; boot=$(boot_epoch)
  for r in "${res[@]}"; do
    exec 8>"$LOCK_DIR/$r.lock" || die "cannot open $LOCK_DIR/$r.lock"
    flock -n 8 || die "$r is busy: a running command holds $LOCK_DIR/$r.lock"
    flock -u 8
    local lease="$LOCK_DIR/$r.lease"
    if [ -f "$lease" ]; then
      local h e p s
      h=$(field holder "$lease"); e=$(field expires "$lease"); p=$(field purpose "$lease")
      s=$(field start "$lease")
      if [ -n "$boot" ] && [ "${s:-0}" -lt "$boot" ]; then
        echo "$r: STALE lease of $h ($p) was written before glolab's last boot" \
             "($(date -u -d "@$boot" +%Y-%m-%dT%H:%MZ)): expired by the reboot, taken over"
      elif [ "${e:-0}" -gt "$start" ]; then
        local unknown=""
        [ -n "$boot" ] || unknown="; glolab's boot time is unknown, so a lease from before a reboot cannot be told apart"
        die "$r is checked out by $h until $(date -u -d "@$e" +%Y-%m-%dT%H:%MZ) ($p)$unknown"
      elif [ "$brk" = 0 ]; then
        die "$r has an EXPIRED check-out by $h ($p): ask them, then pass --break-expired"
      fi
    else
      echo "$r: no lease on record (a lease on tmpfs does not survive glolab's reboot):" \
           "the #428 post is the social lock, so read it before going on"
    fi
  done
  for r in "${res[@]}"; do
    printf 'holder=%s\npurpose=%s\nresources=%s\nstart=%s\nexpires=%s\n' \
      "$holder" "$purpose" "$RESOURCES" "$start" "$end" > "$LOCK_DIR/$r.lease.tmp" &&
      mv -f "$LOCK_DIR/$r.lease.tmp" "$LOCK_DIR/$r.lease" || die "cannot write $LOCK_DIR/$r.lease"
  done
  mkdir -p "$POST_DIR" || die "cannot create $POST_DIR"
  local post="$POST_DIR/checkout-$holder-$start.md"
  "${POLICY[@]}" checkout-text --holder "$holder" --purpose "$purpose" --resources "$RESOURCES" \
      --start "$start" --end "$end" "${TZARG[@]}" > "$post" || die "cannot write $post"
  "${POLICY[@]}" scan "$post" "${SECARG[@]}" || echo "rig_checkout: the CHECK-OUT post holds a secret: fix it before posting" >&2
  echo "claimed $RESOURCES for $holder until $(date -u -d "@$end" +%Y-%m-%dT%H:%MZ)"
  echo "CHECK-OUT post: $post"
  echo "post it with:   $0 post --file $post --confirm"
}

release() {
  local holder="" verdict="" evidence="" note=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --holder) holder=${2:-}; shift ;;
      --verdict) verdict=${2:-}; shift ;;
      --evidence) evidence=${2:-}; shift ;;
      --note) note=${2:-}; shift ;;
      --resources) RESOURCES=${2:-}; shift ;;
      *) usage ;;
    esac
    shift
  done
  [[ $holder =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || die "--holder must be 1-40 of [A-Za-z0-9_.-]"
  case "$verdict" in PASS|FAIL|INVALID|ABORTED|NEEDS-HUMAN) ;; *) die "--verdict must be PASS, FAIL, INVALID, ABORTED or NEEDS-HUMAN" ;; esac
  local r start=0 freed="" IFS_OLD=$IFS; IFS=, read -r -a res <<< "$RESOURCES"; IFS=$IFS_OLD
  with_claims_lock
  for r in "${res[@]}"; do
    local lease="$LOCK_DIR/$r.lease"
    [ -f "$lease" ] || continue
    local h; h=$(field holder "$lease")
    [ "$h" = "$holder" ] || die "$r is checked out by $h, not by $holder: nothing released"
  done
  for r in "${res[@]}"; do
    local lease="$LOCK_DIR/$r.lease"
    [ -f "$lease" ] || continue
    [ "$start" = 0 ] && start=$(field start "$lease")
    rm -f "$lease" && freed="$freed $r"
  done
  mkdir -p "$POST_DIR" || die "cannot create $POST_DIR"
  local t; t=$(now)
  local post="$POST_DIR/checkin-$holder-$t.md"
  "${POLICY[@]}" checkin-text --holder "$holder" --resources "$RESOURCES" --start "${start:-0}" \
      --now "$t" --verdict "$verdict" --evidence "$evidence" --note "$note" > "$post" \
      || die "cannot write $post"
  "${POLICY[@]}" scan "$post" "${SECARG[@]}" || echo "rig_checkout: the CHECK-IN post holds a secret: fix it before posting" >&2
  echo "released${freed:- nothing (no lease of $holder was left)} for $holder; verdict $verdict"
  echo "CHECK-IN post: $post"
  echo "post it with:  $0 post --file $post --confirm"
}

status() {
  local r boot IFS_OLD=$IFS; IFS=, read -r -a res <<< "$RESOURCES"; IFS=$IFS_OLD
  boot=$(boot_epoch)
  for r in "${res[@]}"; do
    if [ -e "$LOCK_DIR/$r.hold" ]; then echo "$r: HUMAN HOLD ($LOCK_DIR/$r.hold)"; fi
    if [ -f "$LOCK_DIR/$r.lease" ]; then
      local stale=""
      [ -n "$boot" ] && [ "$(field start "$LOCK_DIR/$r.lease")" -lt "$boot" ] && stale="STALE (before glolab's last boot): "
      echo "$r: ${stale}checked out by $(field holder "$LOCK_DIR/$r.lease") until" \
           "$(date -u -d "@$(field expires "$LOCK_DIR/$r.lease")" +%Y-%m-%dT%H:%MZ)" \
           "($(field purpose "$LOCK_DIR/$r.lease"))"
    else
      echo "$r: no lease on record (check the #428 post too: a tmpfs lease does not survive a reboot)"
    fi
  done
}

post() {
  local file="" confirm=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --file) file=${2:-}; shift ;;
      --confirm) confirm=1 ;;
      *) usage ;;
    esac
    shift
  done
  [ -f "$file" ] || die "--file must name the post to send"
  "${POLICY[@]}" scan "$file" "${SECARG[@]}" || die "the post holds a secret (see above): not posted"
  local q='mutation($id:ID!,$body:String!){addDiscussionComment(input:{discussionId:$id,body:$body}){comment{url}}}'
  if [ "$confirm" = 0 ]; then
    echo "would run: gh api graphql -f query='$q' -f id=$DISCUSSION_ID -F body=@$file"
    echo "(nothing sent; add --confirm to post)"
    return 0
  fi
  gh api graphql -f query="$q" -f id="$DISCUSSION_ID" -F body=@"$file" --jq .data.addDiscussionComment.comment.url
}

ssh_cmd() {
  local flags=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --flash-step|--abort-path) flags+=("$1") ;;
      --) shift; break ;;
      *) usage ;;
    esac
    shift
  done
  [ $# -gt 0 ] || usage
  "${POLICY[@]}" ssh-check "${flags[@]}" "${SECARG[@]}" -- "$@" || exit 1
  [[ $GLOLAB =~ ^[a-z_][a-z0-9_-]*@[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
    || die "PD_GLOLAB must be user@<IPv4>: never ssh by name"
  [ -r "$KEY" ] || die "no ssh key at $KEY"
  local remote; remote=$(printf '%q ' "$@")
  if [ -n "${PD_RIG_LOG:-}" ]; then
    printf '%s ssh %s %s\n' "$(date -u +%H:%M:%S)" "${flags[*]}" "$remote" \
      | "${POLICY[@]}" redact "${SECARG[@]}" >> "$PD_RIG_LOG" || die "cannot log to $PD_RIG_LOG"
  fi
  exec ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 "$GLOLAB" -- "$remote"
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case "$cmd" in
  claim) claim "$@" ;;
  release) release "$@" ;;
  status) status ;;
  post) post "$@" ;;
  ssh) ssh_cmd "$@" ;;
  redact) exec "${POLICY[@]}" redact "${SECARG[@]}" ;;
  scan) exec "${POLICY[@]}" scan "$@" "${SECARG[@]}" ;;
  *) usage ;;
esac
