// DtmfFeatureCodes.cpp: the DTMF digit-collection state machine, CLASS
// feature codes, and the admin menu, extracted out of RequestsHandler.
#include "DtmfFeatureCodes.hpp"
#include "SipWireUtil.hpp"

#include <cctype>
#include <chrono>

#include "AdminAuth.hpp"
#include "PbxPersist.hpp"
#include "SipClient.hpp"
#include "SipMessage.hpp"
#include "SipMessagePool.hpp"
#include "Session.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_sntp.h"
#include "esp_system.h"
#endif

void DtmfFeatureCodes::onInfo(std::shared_ptr<SipMessage> data)
{
	// --- 1. Parse "Signal=X" from the body -----------------------------------
	const std::string& raw = data->toString();
	char digit = 0;
	{
		size_t sep = raw.find("\r\n\r\n");
		if (sep == std::string::npos) sep = raw.find("\n\n");
		if (sep != std::string::npos)
		{
			std::string body = raw.substr(sep);
			size_t sigPos = body.find("Signal=");
			if (sigPos == std::string::npos) sigPos = body.find("signal=");
			if (sigPos != std::string::npos)
			{
				size_t valIdx = sigPos + 7; // after "Signal="
				while (valIdx < body.size() && body[valIdx] == ' ') ++valIdx;
				if (valIdx < body.size())
				{
					digit = body[valIdx];
				}
			}
		}
	}
	if (digit == 0)
	{
		return; // malformed / no signal — nothing to do
	}

	// --- 2. Look up or create the per-Call-ID accumulator -------------------
	std::string callId(data->getCallID());
	auto& accum = _dtmfState[callId];

	// --- 3. Timeout: reset accumulator if > TIMEOUT_MS since last digit -----
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	TickType_t now = xTaskGetTickCount();
	uint32_t elapsedMs = (now - accum.lastTick) * portTICK_PERIOD_MS;
#else
	uint32_t now = static_cast<uint32_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
	uint32_t elapsedMs = (accum.lastTick == 0) ? 0 : (now - accum.lastTick);
#endif
	if (accum.lastTick != 0 && elapsedMs > DtmfAccum::TIMEOUT_MS)
	{
		accum.digits.clear();
		accum.starCodeFiredAtTick = 0;
	}
	accum.lastTick = now;

	// --- 4. Append digit ----------------------------------------------------
	accum.digits += digit;
	const std::string& seq = accum.digits;
	std::string callerExt(data->getFromNumber());

	// --- 5. Admin menu gate (Task 2C-5): *PIN + 3-digit code ----------------
	// Pattern: * + PIN(4+) + 3-digit-code  (minimum 8 chars total after '*')
	// Admin gate fires only when the caller IS the admin extension.
	if (callerExt == _adminExt && !seq.empty() && seq[0] == '*')
	{
		if (seq == "*4887")
		{
			// PLAN_ADMIN_HTTP_ONLY.md: dedicated star-code (spells HTTP on a phone
			// keypad: H=4 T=8 T=8 P=7), no PIN. *<PIN>#010 does not work on real
			// hardphones — '#' is bound to Send/Call on Yealink (and most SIP
			// phones' keypads), both pre-dial and mid-call, so the sequence never
			// reaches the phone's DTMF-relay path intact. Trust model: registered
			// as the admin extension + signaling from that registration's bound
			// IP is sufficient to open the transport. Opening the transport does
			// NOT bypass PIN/session auth on the endpoints themselves once
			// reachable — this only shortens the no-PIN-needed step to "have the
			// admin handset."
			auto adminClient = _env.findRegistered(_adminExt);
			bool sourceOk = adminClient &&
				data->getSource().sin_addr.s_addr ==
				adminClient->getAddress().sin_addr.s_addr;

			if (!adminClient || !sourceOk)
			{
				_env.log("[admin] HTTP-open DTMF trigger rejected: ext " + _adminExt +
					(adminClient ? " source IP mismatch" : " not registered"), true);
			}
			else
			{
				uint16_t ttlSec = _grantAdminWindow();
				_env.log("[admin] HTTP admin plane opened via DTMF *4887, ext " + _adminExt +
					", ttl=" + std::to_string(ttlSec) + "s");
			}
			// Issue #93: this fires (accept or reject, above) the instant the
			// accumulated sequence equals "*4887" — which can be mid-entry if the
			// admin's actual PIN happens to begin with those four digits. Remember
			// it so the next digits, landing in the fresh accumulator this clear()
			// creates, can be checked for a pattern consistent with a continued
			// *PIN#code the admin never got to finish.
			accum.starCodeFiredAtTick = now;
			accum.digits.clear();
			return;
		}

		// Format: '*' + PIN(>=4 digits) + '#' + 3-digit code [+ confirm digit].
		// The '#' terminates the PIN so its length is unambiguous: we verify the
		// PIN EXACTLY ONCE per completed code. (The old version looped over every
		// candidate PIN length calling verifyPin() for each, so a single normal
		// admin entry charged several failed attempts against the brute-force
		// lockout and could lock the admin out of both DTMF and the dashboard.)
		bool adminMatched = false;
		size_t hashPos = seq.find('#');
		if (hashPos != std::string::npos && hashPos >= 5 && (seq.size() - hashPos - 1) >= 3)
		{
			std::string pinCandidate = seq.substr(1, hashPos - 1);
			std::string rest = seq.substr(hashPos + 1);   // CODE[confirm]
			std::string code = rest.substr(0, 3);
			// PIN must be all digits.
			bool allDigits = !pinCandidate.empty();
			for (char c : pinCandidate)
			{
				if (!std::isdigit(static_cast<unsigned char>(c))) { allDigits = false; break; }
			}
			// Single verify — a wrong PIN is exactly one counted failed attempt.
			if (!allDigits || !AdminAuth::verifyPin(pinCandidate))
			{
				_env.log("[admin] DTMF admin auth failed", true);
				accum.digits.clear();
				return;
			}

			// PIN verified — execute the command code.
			if (code == "001")
			{
				// NTP resync. The inner ESP_IDF_VERSION >= 5.0.0 gate (and its
				// "not available on this IDF version" fallback) is gone: v6.0 is
				// the enforced floor, so esp_sntp_restart always exists here. The
				// outer platform guard stays — this file also builds on the host,
				// where there is no SNTP at all.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
				esp_sntp_restart();
#endif
				_env.log("[admin] NTP sync requested via DTMF");
				adminMatched = true;
			}
			else if (code == "101")
			{
				// Topology switch: toggle wifi_mode between 1 (CLIENT) and 2 (AP).
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
				nvs_handle_t h;
				if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK)
				{
					uint8_t mode = 1;
					nvs_get_u8(h, "wifi_mode", &mode);
					mode = (mode == 1) ? 2 : 1;
					nvs_set_u8(h, "wifi_mode", mode);
					nvs_commit(h);
					nvs_close(h);
				}
				_env.log("[admin] topology switch via DTMF, restarting");
				esp_restart();
#else
				_env.log("[admin] topology switch requested (stub on host)");
#endif
				adminMatched = true;
			}
			else if (code == "200")
			{
				// Extension target config stub
				_env.log("[admin] targets config: dial new ext (stub)");
				adminMatched = true;
			}
			else if (code == "999")
			{
				// Factory reset — requires a follow-up confirm digit '1'.
				if (rest.size() >= 4)
				{
					if (rest[3] == '1')
					{
						_env.log("[admin] factory reset confirmed via DTMF");
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
						nvs_flash_erase();
						esp_restart();
#else
						_env.log("[admin] factory reset (stub on host)");
#endif
					}
					else
					{
						_env.log("[admin] factory reset aborted (confirm != '1')");
					}
					adminMatched = true;
				}
				else
				{
					// Confirm digit not yet received — keep the accumulator and
					// wait. Do NOT set adminMatched (the tail would clear it).
					_env.log("[admin] factory reset: awaiting confirm digit '1'");
					return;
				}
			}
			if (adminMatched)
			{
				accum.digits.clear();
				return;
			}
		}

		// If the sequence starts with *NNNN (4+ digits) but no code matched yet,
		// and the wrong caller is trying, send 403.
	}
	else if (callerExt == _adminExt && accum.starCodeFiredAtTick != 0 &&
	         seq.find('#') != std::string::npos && (seq.size() - seq.find('#') - 1) >= 3)
	{
		// Issue #93: the *4887 star-code just fired for this dialog (above), and
		// the admin kept dialing into something shaped like the tail of an
		// interrupted *PIN#code (no leading '*' — the accumulator that produced
		// this `seq` started fresh when the star-code cleared it). This is only
		// ever a symptom of a PIN that begins "4887": that prefix is reserved
		// (POST /api/admin/set-pin rejects it going forward), but a device
		// provisioned before that guard existed can still be carrying one, and
		// the hash can't be reversed to confirm it — so this is a best-effort,
		// imperfect nudge rather than a definite diagnosis.
		_env.log("[admin] DTMF entry right after *4887 fired looks like an "
			"interrupted *PIN#code from ext " + _adminExt + " — if the admin PIN "
			"begins with 4887 it is shadowed by the HTTP-open star-code and DTMF "
			"admin commands can never complete; rotate it via the dashboard "
			"(POST /api/admin/set-pin) — see docs/THREAT_MODEL.md", true);
		accum.starCodeFiredAtTick = 0;   // one warning per incident
	}
	else if (callerExt != _adminExt && !seq.empty() && seq[0] == '*' &&
	         seq.find('#') != std::string::npos)
	{
		// A non-admin caller attempting the admin-menu pattern (*PIN#…): reject.
		// CLASS service codes (*60/*72/…) have no '#', so they fall through to the
		// per-subscriber feature handling below for any registered caller.
		auto response = sipmsgpool::getMessageFromPool(*data);
		if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
		response->setHeader("SIP/2.0 403 Forbidden");
		response->clearBody();
		std::string activeIp = _env.localIp();
		response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_env.enqueue(data->getSource(), std::move(response));
		accum.digits.clear();
		return;
	}

	// --- 6. CLASS feature code matching (Task 2C-4) --------------------------

	// *60 — Enable Selective Call Rejection (DND=true) for caller's extension.
	if (seq == "*60")
	{
		// Issue #77: route through the same lock-already-held core setDnd()
		// uses (we're already inside _mutex here, via handle()) so the
		// dashboard snapshot refreshes immediately instead of only on the
		// next unrelated HTTP-side setDnd() call.
		_cfg.setDndLocked(callerExt, true);
		accum.digits.clear();
		return;
	}

	// *80 — Disable SCR/DND for caller's extension.
	if (seq == "*80")
	{
		_cfg.setDndLocked(callerExt, false);
		accum.digits.clear();
		return;
	}

	// *73 — Disable CFU for caller's extension.
	if (seq == "*73")
	{
		// Issue #77: setForwardLocked with an empty target clears the
		// "always" trigger exactly like the old inline erase did, but also
		// refreshes the dashboard snapshot and applies the virtual-extension
		// guard that the old inline path skipped.
		_cfg.setForwardLocked(callerExt, "always", "");
		accum.digits.clear();
		return;
	}

	// *69 — Speak last-caller extension: redirect call to echo ext 777 and log CDR lookup.
	if (seq == "*69")
	{
		// Find the last CDR entry where callee == callerExt (i.e. last inbound call).
		std::string lastCaller = _cdr.lastCallerFor(callerExt);
		if (!lastCaller.empty())
		{
			_env.log("*69 last caller for " + callerExt + " is " + lastCaller);
			// Reroute to extension 777 (echo loopback) so the caller hears tones.
			// Find the active session for this Call-ID and redirect its RTP to 777.
			auto session = _env.findSession(callId);
			if (session)
			{
				// Per-session dummy dest (never a shared client) so concurrent
				// star-code/777/440 calls can't clobber each other's destination.
				auto dummy = std::make_shared<SipClient>();
				dummy->reset("777", session->getSrc()
					? session->getSrc()->getAddress() : sockaddr_in{}, 3600);
				session->setDest(dummy);
			}
		}
		else
		{
			_env.log("*69 no last caller found for " + callerExt);
		}
		accum.digits.clear();
		return;
	}

	// *11 — Echo loopback: reroute active call's RTP endpoint to extension 777.
	if (seq == "*11")
	{
		auto session = _env.findSession(callId);
		if (session)
		{
			auto src = session->getSrc();
			if (src)
			{
				// Per-session dummy dest (never a shared client) — see *69 above.
				auto dummy = std::make_shared<SipClient>();
				dummy->reset("777", src->getAddress(), 3600);
				session->setDest(dummy);
				_env.log("*11 echo loopback for call " + callId);
			}
		}
		accum.digits.clear();
		return;
	}

	// *72NNNN — Enable CFU for caller's extension to NNNN (4+ digits after *72).
	// Requires the full sequence to be collected; we match once it's ≥6 chars and
	// none of the above shorter patterns matched.
	if (seq.size() >= 6 && seq[0] == '*' && seq[1] == '7' && seq[2] == '2')
	{
		std::string target = seq.substr(3);
		if (target.size() >= 4 && _env.validAor(target))
		{
			// Issue #77: setForwardLocked applies the same table-full guard and
			// the virtual-extension guard setForward() has always had (which
			// this inline path used to skip), and refreshes the dashboard
			// snapshot immediately instead of leaving it stale.
			_cfg.setForwardLocked(callerExt, "always", target);
			accum.digits.clear();
			return;
		}
		// else: keep accumulating (target not yet 4 digits)
	}
}

void DtmfFeatureCodes::forgetCall(std::string_view callId)
{
	// DTMF accumulators are keyed by Call-ID and share the dialog lifecycle; drop
	// this dialog's entry so _dtmfState can't grow unbounded across calls (Fix #4).
	_dtmfState.erase(std::string(callId));
}

void DtmfFeatureCodes::sweepStale()
{
	// Belt-and-suspenders (Fix #4): drop DTMF accumulators whose dialog is gone,
	// in case a teardown path bypassed forgetCall(). Bounded by the small session pool.
	for (auto dit = _dtmfState.begin(); dit != _dtmfState.end(); )
	{
		if (!_env.findSession(dit->first)) dit = _dtmfState.erase(dit);
		else ++dit;
	}
}

void DtmfFeatureCodes::load()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return;
	}
	char buf[32] = {0};
	size_t len = sizeof(buf);
	esp_err_t err = nvs_get_str(h, "admin_ext", buf, &len);
	nvs_close(h);
	if (err == ESP_OK && buf[0] != '\0')
	{
		_adminExt = buf;
	}
	// else: keep the in-class default "1001"
#endif
}

void DtmfFeatureCodes::saveAdminExt(const std::string& ext)
{
	_adminExt = ext;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "admin_ext", ext.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}

std::string DtmfFeatureCodes::adminExt() const
{
	return _adminExt;
}
