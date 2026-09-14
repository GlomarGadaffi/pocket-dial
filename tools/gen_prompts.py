#!/usr/bin/env python3
"""Generate IVR voice prompts from ElevenLabs as 8 kHz G.711 u-law.

Usage:
  python tools/gen_prompts.py --key-file PATH [--voice VOICE_ID] [--out DIR] [--only NAME ...]

Writes <out>/<name>.ulaw (raw u-law, 8 kHz mono, what the board plays) and
<out>/<name>.wav (decoded to 16-bit PCM, for listening on a PC),
plus <out>/manifest.json. Existing files are skipped unless --force.
The API key is read from the key file line that starts with "elevenlabs".
"""
import argparse, json, os, struct, sys, time, urllib.request

PROMPTS = {
    # 1. auto-attendant
    "aa_greeting": "Thank you for calling. If you know your party's extension, dial it now.",
    "aa_menu": "For the directory, press 9. To reach an operator, press 0.",
    "aa_connecting": "One moment while I connect you.",
    "aa_no_answer": "That extension is not answering.",
    "aa_busy": "That extension is busy.",
    "aa_invalid": "I'm sorry, that is not a valid entry. Please try again.",
    "aa_timeout": "I didn't receive a response.",
    "aa_goodbye": "Goodbye.",
    "aa_closed": "Our office is currently closed. Please call back during business hours.",
    # 2. call progress
    "cp_not_in_service": "The number you dialed is not in service.",
    "cp_invalid_number": "The number you dialed is invalid.",
    "cp_all_lines_busy": "All lines are busy. Please try again later.",
    "cp_cannot_complete": "Your call cannot be completed as dialed.",
    "cp_dnd": "This extension has do not disturb enabled.",
    "cp_please_hold": "Please hold.",
    "cp_transferring": "Transferring your call.",
    "cp_disconnected": "The other party has disconnected.",
    # 3. feature codes
    "fc_cfwd_on": "Call forwarding is on.",
    "fc_cfwd_off": "Call forwarding is off.",
    "fc_cfwd_busy_on": "Forward on busy is on.",
    "fc_cfwd_busy_off": "Forward on busy is off.",
    "fc_cfwd_noanswer_on": "Forward on no answer is on.",
    "fc_cfwd_noanswer_off": "Forward on no answer is off.",
    "fc_dnd_on": "Do not disturb is on.",
    "fc_dnd_off": "Do not disturb is off.",
    "fc_callback": "Calling your last caller.",
    "fc_callback_none": "No previous caller is available.",
    "fc_echo_start": "Echo test. Speak after the tone.",
    "fc_echo_done": "Echo test complete.",
    "fc_activated": "Feature activated.",
    "fc_deactivated": "Feature deactivated.",
    "fc_unknown": "That feature code is not recognized.",
    # 4. park and pickup
    "pk_parked_on": "Your call is parked on orbit",
    "pk_none": "No parked call at that orbit.",
    "pk_full": "All park orbits are full.",
    "pk_retrieving": "Retrieving parked call.",
    "pu_none_ringing": "No calls are ringing in your group.",
    "pu_ext_not_ringing": "That extension is not ringing.",
    # 5. conference
    "cf_welcome_first": "Welcome to the conference. You are the first participant.",
    "cf_joining": "You are now joining the conference.",
    "cf_full": "The conference is full.",
    "cf_joined": "A participant has joined.",
    "cf_left": "A participant has left.",
    "cf_enter_pin": "Please enter the conference PIN, followed by pound.",
    "cf_invalid_pin": "Invalid PIN.",
    # 6. paging
    "pg_unavailable": "Paging zone unavailable.",
    # 7. admin / provisioning
    "ad_enter_pin": "Enter your admin PIN, followed by pound.",
    "ad_invalid_pin": "Invalid PIN. Access denied.",
    "ad_menu": "Admin menu. Press 1 for status, 2 for network, 3 to reboot, or 9 to exit.",
    "ad_rebooting": "Rebooting.",
    "ad_saved": "Saved.",
    "ad_cancelled": "Cancelled.",
    "pv_enter_ext": "Enter the extension number to provision, followed by pound.",
    "pv_done": "Extension provisioned.",
    # 8. voicemail
    "vm_unavailable": "The person you are calling is unavailable. Please leave a message after the tone.",
    "vm_full": "Mailbox full.",
    "vm_saved": "Your message has been saved.",
    "vm_you_have": "You have",
    "vm_new_message": "new message.",
    "vm_new_messages": "new messages.",
    "vm_no_messages": "You have no new messages.",
    "vm_controls": "Press 1 to replay, 7 to delete, or 9 to save.",
    # 9. fragments
    # digits without punctuation so they read flat mid-sentence when concatenated
    "n_0": "zero", "n_1": "one", "n_2": "two", "n_3": "three", "n_4": "four",
    "n_5": "five", "n_6": "six", "n_7": "seven", "n_8": "eight", "n_9": "nine",
    "n_oh": "oh",
    # counting words for natural numbers (voicemail counts etc)
    "n_10": "ten", "n_11": "eleven", "n_12": "twelve", "n_13": "thirteen", "n_14": "fourteen",
    "n_15": "fifteen", "n_16": "sixteen", "n_17": "seventeen", "n_18": "eighteen", "n_19": "nineteen",
    "n_20": "twenty", "n_30": "thirty", "n_40": "forty", "n_50": "fifty",
    "n_60": "sixty", "n_70": "seventy", "n_80": "eighty", "n_90": "ninety",
    "n_hundred": "hundred", "n_thousand": "thousand", "w_and": "and",
    "w_star": "star.", "w_pound": "pound.", "w_extension": "extension",
    "w_orbit": "orbit", "w_zone": "zone", "w_conference_room": "conference room",
    "w_missed_call": "missed call.", "w_missed_calls": "missed calls.",
}

DEFAULT_VOICE = "EXAVITQu4vr4xnSDxMaL"  # ElevenLabs stock "Sarah"
MODEL = "eleven_multilingual_v2"


def read_key(path):
    for line in open(path, encoding="utf-8"):
        if line.lower().startswith("elevenlabs"):
            return line.split()[1].strip()
    sys.exit("no 'elevenlabs <key>' line in " + path)


def tts(key, voice, text):
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice}?output_format=ulaw_8000"
    body = json.dumps({"text": text, "model_id": MODEL,
                       "voice_settings": {"stability": 0.6, "similarity_boost": 0.8}}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "xi-api-key": key, "Content-Type": "application/json", "Accept": "audio/basic"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            sys.exit(f"HTTP {e.code}: {e.read()[:300]}")


def trim(data, thresh=8, keep=800):
    """Trim leading/trailing u-law silence, keeping `keep` samples (100 ms) each side.
    u-law 0xFF/0x7F is digital zero; distance from it approximates amplitude."""
    def loud(b):
        return abs((b & 0x7F) - 0x7F) > thresh
    n = len(data)
    s = next((i for i in range(n) if loud(data[i])), 0)
    e = next((i for i in range(n - 1, -1, -1) if loud(data[i])), n - 1) + 1
    return data[max(0, s - keep):min(n, e + keep)]


def ulaw_to_pcm16(ulaw):
    out = bytearray()
    for b in ulaw:
        b = ~b & 0xFF
        sign, exp, mant = b & 0x80, (b >> 4) & 7, b & 0x0F
        v = ((mant << 3) + 0x84) << exp
        v -= 0x84
        v = -v if sign else v
        out += struct.pack("<h", max(-32768, min(32767, v)))
    return bytes(out)


def write_wav(path, ulaw):
    """Standard 16-bit PCM WAV at 8 kHz for listening on a PC. Windows players
    truncate WAV format 7 (u-law) files, so the u-law bytes are decoded first."""
    pcm = ulaw_to_pcm16(ulaw)
    with open(path, "wb") as f:
        f.write(b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE")
        f.write(b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16))
        f.write(b"data" + struct.pack("<I", len(pcm)) + pcm)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--voice", default=DEFAULT_VOICE)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "assets", "prompts"))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    key = read_key(a.key_file)
    os.makedirs(a.out, exist_ok=True)
    names = a.only or list(PROMPTS)
    manifest, chars = {}, 0
    for name in names:
        text = PROMPTS[name]
        raw = os.path.join(a.out, name + ".ulaw")
        if os.path.exists(raw) and not a.force:
            data = open(raw, "rb").read()
        else:
            data = trim(tts(key, a.voice, text))
            open(raw, "wb").write(data)
            write_wav(os.path.join(a.out, name + ".wav"), data)
            chars += len(text)
            print(f"{name:24s} {len(data)/8000:5.2f}s  {text}")
        manifest[name] = {"text": text, "bytes": len(data), "seconds": round(len(data) / 8000, 2)}
    json.dump({"voice": a.voice, "model": MODEL, "format": "ulaw_8000", "prompts": manifest},
              open(os.path.join(a.out, "manifest.json"), "w"), indent=2)
    total = sum(m["bytes"] for m in manifest.values())
    print(f"\n{len(manifest)} prompts, {total/1024:.0f} KB total, {chars} characters billed this run")


if __name__ == "__main__":
    main()
