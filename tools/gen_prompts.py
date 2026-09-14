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
    "vm_greeting_default": "Hello. The person you are trying to reach is not available right now. "
                           "Please leave your name, number, and a brief message after the tone, "
                           "and they will return your call as soon as possible.",
    "vm_greeting_ext_prefix": "You have reached extension",
    "vm_greeting_ext_suffix": "Please leave a message after the tone.",
    "vm_greeting_busy": "The person you are trying to reach is on another call. Please leave a message after the tone.",
    "vm_full": "Mailbox full.",
    "vm_saved": "Your message has been saved.",
    "vm_you_have": "You have",
    "vm_new_message": "new message.",
    "vm_new_messages": "new messages.",
    "vm_no_messages": "You have no new messages.",
    "vm_controls": "Press 1 to replay, 7 to delete, or 9 to save.",
    # leaving a message
    "vm_record_start": "Begin speaking after the tone. Press pound when you are finished.",
    "vm_record_maxlen": "You have reached the maximum message length.",
    "vm_record_tooshort": "Your message was too short and was not saved.",
    "vm_record_review": "To send your message, press 1. To listen to it, press 2. To re-record, press 3.",
    "vm_record_sent": "Your message has been sent. Goodbye.",
    # mailbox login
    "vm_login_enter_pw": "Please enter your password, followed by pound.",
    "vm_login_enter_mailbox": "Please enter your mailbox number, followed by pound.",
    "vm_login_bad_pw": "Incorrect password. Please try again.",
    "vm_login_locked": "Too many incorrect attempts. Goodbye.",
    "vm_welcome": "Welcome to your mailbox.",
    # main menu
    "vm_main_menu": "To listen to your messages, press 1. To change your greeting, press 2. "
                    "To change your password, press 3. To exit, press star.",
    "vm_saved_count_prefix": "and",  # "you have 2 new messages and 5 saved messages"
    "vm_saved_message": "saved message.",
    "vm_saved_messages": "saved messages.",
    # playback loop
    "vm_first_message": "First message.",
    "vm_next_message": "Next message.",
    "vm_last_message": "Last message.",
    "vm_end_of_messages": "End of messages.",
    "vm_message_from_ext": "Message from extension",
    "vm_message_from_unknown": "Message from an unknown caller.",
    "vm_message_from_outside": "Message from an outside number.",
    "vm_playback_menu": "To replay, press 1. To save, press 2. To delete, press 7. "
                        "For the next message, press pound. To return to the main menu, press star.",
    "vm_message_deleted": "Message deleted.",
    "vm_message_restored": "Message restored.",
    "vm_message_kept": "Message saved.",
    # greeting management
    "vm_greeting_menu": "To listen to your current greeting, press 1. To record a new greeting, "
                        "press 2. To use the default greeting, press 3. To return, press star.",
    "vm_greeting_record": "Record your greeting after the tone. Press pound when you are finished.",
    "vm_greeting_review": "To keep this greeting, press 1. To listen to it, press 2. To re-record, press 3.",
    "vm_greeting_saved": "Your greeting has been saved.",
    "vm_greeting_default_set": "The default greeting is now active.",
    # password change
    "vm_pw_new": "Enter your new password, followed by pound.",
    "vm_pw_confirm": "Re-enter your new password, followed by pound.",
    "vm_pw_mismatch": "The passwords did not match. Please try again.",
    "vm_pw_changed": "Your password has been changed.",
    "vm_pw_tooshort": "Your password must be at least four digits.",
    # misc
    "vm_skip_greeting": "To skip this greeting, press pound.",
    "vm_operator": "To reach an operator, press 0.",
    "vm_exit": "Thank you. Goodbye.",
    # 10. transfer / forward entry
    "tr_enter_dest": "Enter the extension to transfer to, followed by pound.",
    "tr_complete": "Transfer complete.",
    "tr_failed": "The transfer could not be completed. Reconnecting you.",
    "tr_to_voicemail": "Your call is being transferred to voicemail.",
    "fw_enter_number": "Enter the forwarding number, followed by pound.",
    "fw_forwarding_to": "Calls will be forwarded to",
    "fw_invalid": "That forwarding number is invalid.",
    "fw_your_call_forwarded": "Your call is being forwarded.",
    # 11. camp-on / waiting / queue style holding
    "wt_party_busy_options": "The party you are calling is on another call. To wait, press 1. "
                             "To leave a message, press 2. To reach an operator, press 0.",
    "wt_stay_on_line": "Please stay on the line. Your call will be answered in the order it was received.",
    "wt_continue_hold": "Please continue to hold. Your call is important to us.",
    "wt_still_busy": "The party is still busy. Please continue to hold.",
    "wt_now_available": "The party is now available. Connecting you.",
    "wt_call_waiting": "You have another call waiting.",
    "wt_return_press_star": "To return to your call, press star.",
    "wt_no_agents": "No one is available to take your call right now.",
    # 12. call screening / blocking
    "sc_say_name": "Please say your name after the tone.",
    "sc_screening_hold": "Please hold while we announce your call.",
    "sc_announce_prefix": "You have a call from",
    "sc_announce_options": "To accept, press 1. To send to voicemail, press 2.",
    "sc_rejected": "The party is unable to take your call.",
    "sc_blocked": "This number is not accepted. Goodbye.",
    "sc_anonymous_rejected": "Anonymous calls are not accepted. Please unblock your caller ID and try again.",
    # 13. directory
    "dir_intro": "Directory. Enter the first three letters of the person's last name.",
    "dir_no_match": "No matches were found.",
    "dir_select": "To select this person, press 1. For the next match, press pound.",
    "dir_connecting": "Connecting you to extension",
    # 14. speed dial
    "sd_enter_slot": "Enter the speed dial number.",
    "sd_enter_dest": "Enter the destination number, followed by pound.",
    "sd_saved": "Speed dial saved.",
    "sd_not_set": "That speed dial is not set.",
    # 15. hot desk / login
    "hd_enter_ext": "Enter your extension number, followed by pound.",
    "hd_enter_pin": "Enter your PIN, followed by pound.",
    "hd_logged_in": "You are now logged in.",
    "hd_logged_out": "You are now logged out.",
    # 16. trunk / network / system state
    "sys_trunk_down": "Outside lines are currently unavailable. Please try again later.",
    "sys_trunk_busy": "All outside lines are in use. Please try again later.",
    "sys_emergency": "Connecting you to emergency services.",
    "sys_not_permitted": "You are not permitted to dial this number.",
    "sys_error": "A system error occurred. Please try again.",
    "sys_timeout": "Your session has timed out. Goodbye.",
    "sys_please_wait": "Please wait.",
    "sys_ip_prefix": "The IP address is",
    "sys_dot": "dot",
    "sys_ext_prefix": "Your extension number is",
    "sys_registered": "Registered.",
    "sys_not_registered": "Not registered.",
    "sys_uptime_prefix": "System uptime is",
    "sys_days": "days", "sys_hours": "hours", "sys_minutes": "minutes",
    "sys_calls_active_prefix": "Active calls:",
    "sys_wakeup": "This is your wake-up call.",
    "sys_recording_notice": "This call may be recorded.",
    "sys_test_ok": "Audio test successful.",
    # 17. conference extras
    "cf_muted": "You are muted.",
    "cf_unmuted": "You are unmuted.",
    "cf_alone": "You are the only participant in the conference.",
    "cf_ended": "The conference has ended.",
    "cf_count_prefix": "There are",
    "cf_participants": "participants in the conference.",
    "cf_participant": "participant in the conference.",
    "cf_locked": "The conference is locked.",
    # 18. date / time fragments (message timestamps, time routing)
    "t_at": "at", "t_today": "today", "t_yesterday": "yesterday", "t_oclock": "o'clock",
    "t_am": "A M", "t_pm": "P M", "t_noon": "noon", "t_midnight": "midnight",
    "t_received": "Received",
    "d_monday": "Monday", "d_tuesday": "Tuesday", "d_wednesday": "Wednesday",
    "d_thursday": "Thursday", "d_friday": "Friday", "d_saturday": "Saturday", "d_sunday": "Sunday",
    "m_1": "January", "m_2": "February", "m_3": "March", "m_4": "April", "m_5": "May", "m_6": "June",
    "m_7": "July", "m_8": "August", "m_9": "September", "m_10": "October", "m_11": "November", "m_12": "December",
    "o_1": "first", "o_2": "second", "o_3": "third", "o_4": "fourth", "o_5": "fifth", "o_6": "sixth",
    "o_7": "seventh", "o_8": "eighth", "o_9": "ninth", "o_10": "tenth", "o_11": "eleventh", "o_12": "twelfth",
    "o_13": "thirteenth", "o_14": "fourteenth", "o_15": "fifteenth", "o_16": "sixteenth", "o_17": "seventeenth",
    "o_18": "eighteenth", "o_19": "nineteenth", "o_20": "twentieth", "o_21": "twenty first", "o_22": "twenty second",
    "o_23": "twenty third", "o_24": "twenty fourth", "o_25": "twenty fifth", "o_26": "twenty sixth",
    "o_27": "twenty seventh", "o_28": "twenty eighth", "o_29": "twenty ninth", "o_30": "thirtieth", "o_31": "thirty first",
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
