// DtmfFeatureCodes.cpp: the DTMF digit-collection state machine, CLASS
// feature codes, and the admin menu, extracted out of RequestsHandler.
#include "DtmfFeatureCodes.hpp"
#include "SipWireUtil.hpp"

#include <cctype>
#include <chrono>

#include "AdminAuth.hpp"
#include "CdrArchive.hpp"
#include "CoreDumpStore.hpp"
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

	onDigit(data->getCallID(), digit, DigitSource::Info, nowTickMs(), data);
}

uint32_t DtmfFeatureCodes::nowTickMs()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	return static_cast<uint32_t>(xTaskGetTickCount());
#else
	return static_cast<uint32_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
#endif
}

void DtmfFeatureCodes::onDigit(std::string_view callIdView, char digit,
	DigitSource source, uint32_t arrivedTick, const std::shared_ptr<SipMessage>& data)
{
	// --- 2. Look up or create the per-Call-ID accumulator -------------------
	std::string callId(callIdView);
	auto& accum = _dtmfState[callId];

	// --- 2a. Dual-source de-duplication -------------------------------------
	// Same digit, other source, inside the window: this is the twin of a press
	// already counted, not a second press. See DtmfAccum's note for why the rule
	// is this narrow.
	const uint32_t nowTick = arrivedTick;
	if (accum.lastDigit == digit &&
	    accum.lastSource != 0 &&
	    accum.lastSource != static_cast<uint8_t>(source))
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		const uint32_t sinceMs =
			(nowTick - accum.lastAcceptedTick) * portTICK_PERIOD_MS;
#else
		const uint32_t sinceMs = nowTick - accum.lastAcceptedTick;
#endif
		if (sinceMs <= DtmfAccum::DUP_WINDOW_MS)
		{
			return;   // duplicate of a press we already have
		}
	}

	// --- 3. Timeout: reset accumulator if > TIMEOUT_MS since last digit -----
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	TickType_t now = static_cast<TickType_t>(nowTick);
	uint32_t elapsedMs = (now - accum.lastTick) * portTICK_PERIOD_MS;
#else
	uint32_t now = nowTick;
	uint32_t elapsedMs = (accum.lastTick == 0) ? 0 : (now - accum.lastTick);
#endif
	if (accum.lastTick != 0 && elapsedMs > DtmfAccum::TIMEOUT_MS)
	{
		accum.digits.clear();
	}
	accum.lastTick = now;

	// --- 4. Append digit ----------------------------------------------------
	accum.digits += digit;
	accum.lastDigit        = digit;
	accum.lastSource       = static_cast<uint8_t>(source);
	accum.lastAcceptedTick = now;
	const std::string& seq = accum.digits;
	// The caller's extension. An INFO carries it in From; an RFC 4733 digit
	// arrives with only a Call-ID, so resolve it off the live session — the same
	// dialog the accumulator is keyed by.
	std::string callerExt;
	if (data)
	{
		callerExt = std::string(data->getFromNumber());
	}
	else if (auto session = _env.findSession(callId); session && session->getSrc())
	{
		callerExt = session->getSrc()->getNumber();
	}

	// --- 5. Admin menu gate (Task 2C-5): *PIN + 3-digit code ----------------
	// Pattern: * + PIN(4+) + 3-digit-code  (minimum 8 chars total after '*')
	// Admin gate fires only when the caller IS the admin extension.
	if (callerExt == _adminExt && !seq.empty() && seq[0] == '*')
	{
		// Format: '*' + PIN(>=4 digits) + '#' + 3-digit code [+ confirm digit].
		// The '#' terminates the PIN so its length is unambiguous: we verify the
		// PIN EXACTLY ONCE per completed code. (The old version looped over every
		// candidate PIN length calling verifyDtmfPin() for each, so a single
		// normal admin entry charged several failed attempts against the
		// brute-force lockout and could lock the admin out of both DTMF and the
		// dashboard — verifyDtmfPin() shares its attempt-bucket table with the
		// web login's verifyCredential(), so that risk is real in both directions.)
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
			// verifyDtmfPin() always fails until a DTMF PIN has been explicitly
			// set (AdminAuth::setDtmfPin) — there is no default, so this whole
			// menu is unreachable on a freshly-flashed or freshly-reset device.
			if (!allDigits || !AdminAuth::verifyDtmfPin(pinCandidate))
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
						// Issue #222: wipe the SD CDR archive too, so this door and the
						// HTTP one (HttpServer::sendApiFactoryReset) forget the same
						// things. nvs_flash_erase() below takes out the NVS "cdrlog"
						// ring along with every other namespace, but it never touches
						// the card's filesystem, so without this line a DTMF reset left
						// a full dated plaintext call history on the SD while the HTTP
						// reset wiped it -- same "forget everything" action, different
						// outcome depending on which door was used.
						//
						// This is a deliberate, scoped EXCEPTION to CdrArchive.hpp's SD
						// write-discipline rule ("no blocking file I/O on the SIP
						// thread / under RequestsHandler::_mutex"). The rule exists so
						// directory I/O can never stall live call handling. Here the
						// very next statement is esp_restart(): the SIP thread, the
						// mutex and every call it was protecting are about to cease to
						// exist, so the only thing the opendir/unlink sweep can delay is
						// the reboot itself. No packet that arrives during the sweep
						// would have been serviced anyway. wipeAll() also takes the
						// archive's drain/wipe mutex, so it cannot race the writer task
						// mid-drain (a std::mutex on ESP-IDF is a FreeRTOS mutex with
						// priority inheritance, so the low-priority writer task cannot
						// hold the SIP thread hostage either). Ordering: SD first, then
						// NVS, then restart -- the NVS erase is fast and unconditional,
						// so putting the (possibly slower, card-dependent) SD sweep
						// first means both wipes are attempted before power is cut.
						// Kept OUTSIDE the platform guard: on host wipeAll() reaches the
						// test-installed Sink (or is a no-op with none), which is what
						// makes this path's wipe contract host-testable -- see
						// DtmfFactoryReset_test.cpp.
						cdrarchive::wipeAll();
						// #437 review: the HTTP door erases the last coredump (a copy of
						// task stacks, which can hold any secret in the clear), and
						// nvs_flash_erase() below does not reach the coredump partition,
						// so this door must erase it too. A flash erase on this thread is
						// safe: every esp_main variant creates sip_server_task with an
						// internal-RAM stack (plain xTaskCreatePinnedToCore). Its result
						// is ignored for the same reason FactoryReset ignores it: a board
						// whose partition table predates #382 has no coredump partition.
						// Outside the platform guard, so the host suite can pin it.
						(void)CoreDumpStore::erase();
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
						nvs_flash_erase();
						esp_restart();
#else
						_env.log("[admin] factory reset (NVS erase + restart stubbed on host)");
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
	else if (callerExt != _adminExt && !seq.empty() && seq[0] == '*' &&
	         seq.find('#') != std::string::npos)
	{
		// A non-admin caller attempting the admin-menu pattern (*PIN#…): reject.
		// CLASS service codes (*60/*72/…) have no '#', so they fall through to the
		// per-subscriber feature handling below for any registered caller.
		//
		// The 403 is only sendable when the digit arrived as a SIP INFO, because
		// it is the response to THAT request. An RFC 4733 digit came over RTP and
		// has no request to answer — there is no such thing as a SIP response to
		// a media packet. The refusal still takes effect either way: clearing the
		// accumulator is what actually stops the sequence from completing, and
		// the caller simply gets silence instead of a 403 they were never going
		// to surface to the user anyway.
		if (data)
		{
			auto response = sipmsgpool::getMessageFromPool(*data);
			if (!response) return;   // pool exhausted: drop, peer retransmits (#101A)
			response->setHeader("SIP/2.0 403 Forbidden");
			response->clearBody();
			std::string activeIp = _env.localIp();
			response->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_env.enqueue(data->getSource(), std::move(response));
		}
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
				// Drawn from the virtual-peer pool rather than make_shared'd:
				// onInfo() runs on the SIP packet path like every other handler,
				// so invariant 1 (zero heap allocation in the packet hot path)
				// applies here too (drawbridge audit #70).
				//
				// allocVirtualPeer can return nullptr — pocket-dial's allocator
				// refuses past POCKETDIAL_VPEER_HEAP_FALLBACK_MAX rather than
				// heap-falling-back forever the way drawbridge's does. There is no
				// response to fail here (this is a mid-dialog DTMF feature, not a
				// transaction), so the graceful degradation is to leave the call's
				// existing destination alone: the caller simply doesn't get the
				// echo, instead of ending up on a session whose dest is null and
				// whose teardown/CDR paths dereference it.
				auto dummy = _env.allocVirtualPeer("777", session->getSrc()
					? session->getSrc()->getAddress() : sockaddr_in{});
				if (dummy)
				{
					session->setDest(dummy);
				}
				else
				{
					_env.log("*69 virtual-peer pool exhausted, echo reroute skipped for "
						+ callerExt, true);
				}
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
				// Per-session dummy dest from the virtual-peer pool, null-checked
				// — see *69 above for both (drawbridge audit #70).
				auto dummy = _env.allocVirtualPeer("777", src->getAddress());
				if (!dummy)
				{
					_env.log("*11 virtual-peer pool exhausted, echo loopback skipped for call "
						+ callId, true);
					accum.digits.clear();
					return;
				}
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
