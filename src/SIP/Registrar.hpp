#ifndef REGISTRAR_HPP
#define REGISTRAR_HPP

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "PbxEnv.hpp"
#include "SipMessage.hpp"

// ── Registrar admission + adopted-device registry (STAGE 2) ───────────────────
// The REGISTER-side state machine extracted from RequestsHandler: runtime
// registrar policy (Learn / Secure; open is retired, #500), digest challenge/verify, and the
// Learn-mode TOFU + MAC-lock adoption lifecycle with its NVS-persisted device
// table.
//
// Locking: unless noted otherwise every method assumes the caller holds the
// engine's _mutex — the same convention as the monolith this came from. The
// mode itself is atomic so getMode() stays lock-free for the dashboard.
class Registrar
{
public:
	// The open registrar (value 0: accept every REGISTER, no challenge) is
	// RETIRED (#500, desmo 2026-09-27). The byte 0 still decodes (decodeStored),
	// as Learn, so a board that stored it keeps admitting its phones -- but no
	// code path can select open any more, which the missing enumerator proves.
	enum class Mode : uint8_t
	{
		Learn  = 1,   // TOFU + MAC-lock: adopt unknown devices, enforce secured ones
		Secure = 2,   // require digest auth for every provisioned extension
	};

	// NVS byte -> mode. 1 and 2 are themselves; 0 (the retired open) is Learn,
	// flagged so loadMode() rewrites it once. Anything else is not a mode.
	struct StoredMode
	{
		bool valid;
		Mode mode;
		bool wasRetiredOpen;
	};
	static StoredMode decodeStored(uint8_t v)
	{
		if (v == 0) return {true, Mode::Learn, true};
		if (v == static_cast<uint8_t>(Mode::Learn)) return {true, Mode::Learn, false};
		if (v == static_cast<uint8_t>(Mode::Secure)) return {true, Mode::Secure, false};
		return {false, Mode::Learn, false};
	}

	enum class DeviceState : uint8_t
	{
		Learned = 0,   // TOFU: seen + accepted, not yet locked to digest auth
		Secured = 1,   // promoted: MAC-locked + digest-enforced for its extension
	};

	struct AdoptedDevice
	{
		std::string mac;         // 12 lowercase hex chars
		std::string extension;   // the AOR it last registered as
		DeviceState state = DeviceState::Learned;
		bool online = false;     // currently has a live registration binding
		bool locked = false;     // #440: Learn has bound its extension to this MAC
		bool shared = false;     // #440: this MAC registered >1 extension (NAT) -- never locked
		bool assigned = false;   // #826: zero-touch row its MAC has not registered yet
	};

	// RetryLater (#515, #440): admitLearn has already enqueued a 503 + Retry-After.
	enum class AuthDecision : uint8_t { Accept, Challenge, Reject, RetryLater };

	Registrar(PbxEnv& env, Mode defaultMode) : _env(env), _mode(defaultMode) {}

	// ── Boot-time default (issue #397) ────────────────────────────────────────
	// What mode a board boots in when NVS has no reg_mode, and whether to write
	// it back. Pure, so the host suite tests the rule the board runs.
	//   stored mode present            -> that mode, nothing written
	//   no stored mode, trusted store  -> Learn, persisted
	//   no stored mode, Uncertain store (unreadable, failed/downgrade schema)
	//                                  -> Learn, NOT persisted: re-decided next boot
	// A missing key is also what every failed write looks like, so it fails safe
	// (#441 review). Open no longer exists at all (#500): a deployed pre-#397
	// board that ran it gets Learn written by the schema v1 -> v2 migration
	// (DeviceConfig.cpp, migrateRetireOpenRegistrar).
	enum class BootSchema : uint8_t { FreshInstall, Upgraded, Uncertain };
	struct BootModeDecision
	{
		Mode mode;
		bool persist;
	};
	static BootModeDecision chooseBootMode(bool haveStored, Mode stored, BootSchema schema);

	// ── Mode ──────────────────────────────────────────────────────────────────
	// setMode persists write-through (caller holds _mutex); getMode is lock-free.
	void setMode(Mode mode);
	Mode getMode() const { return _mode.load(std::memory_order_relaxed); }
	void loadMode();      // boot-time NVS reload; runs single-threaded pre-dispatch

	// ── REGISTER admission ────────────────────────────────────────────────────
	// Secure-mode admission: challenge + verify digest for `ext`. Enqueues the
	// 401 (with WWW-Authenticate) itself when challenging.
	AuthDecision admitSecure(const std::shared_ptr<SipMessage>& data,
		const std::string& ext, std::string& outRejectReason);
	// Learn-mode admission: resolves the source MAC, applies TOFU + MAC-lock and
	// returns the digest decision. Records/updates the adoption entry -- poll
	// consumeDevicesChange() afterwards to mirror the snapshot. Issue #440:
	//   - an extension is LOCKED to a MAC on its second REGISTER from that same
	//     resolved MAC (never the first, never on an ARP miss), and only if no
	//     earlier-adopted device row holds the extension (first claim wins);
	//   - another MAC registering a locked (or Secured) extension -> Reject;
	//   - an ARP miss for a locked extension -> Accept if `fromRegisteredAddress`
	//     (the source IP:port is the extension's live binding: the owner's own
	//     refresh), else a 503 + Retry-After is enqueued here and RetryLater
	//     ("response already sent") is returned: retryable, never a lockout,
	//     and sending it makes lwIP ARP the source;
	//   - an UNLOCKED MAC that registers a second extension is marked shared
	//     (the signature of phones behind one NAT router) and never locks;
	//   - a first-packet ARP miss for an unlocked extension still Accepts;
	//   - #507: a Secured extension or device is always digest-checked
	//     (admitSecure), on an ARP miss too, and its record never moves.
	// #515: adopting a NEW MAC spends a token (kAdoptBurst, one back per
	// kAdoptRefill); with none left it answers 503 + Retry-After and returns
	// RetryLater. Known MACs never spend one. `now` is a test seam.
	static constexpr uint8_t kAdoptBurst = 4;
	static constexpr std::chrono::seconds kAdoptRefill{15};   // 4 per minute
	AuthDecision admitLearn(const std::shared_ptr<SipMessage>& data,
		const std::string& ext, std::string& outRejectReason,
		std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
		bool fromRegisteredAddress = false);
	// Emit a 401 Unauthorized with a fresh WWW-Authenticate challenge. `stale`
	// answers an expired-but-valid nonce.
	void sendChallenge(const std::shared_ptr<SipMessage>& data, bool stale);
	// Emit a 403 Forbidden with a reason phrase.
	void sendForbidden(const std::shared_ptr<SipMessage>& data, const std::string& reason);
	// Emit a 503 Service Unavailable with Retry-After (#515, #440). Kept short: per
	// RFC 3261 §21.5.4 the phone holds off the WHOLE server for that long.
	void sendRetryLater(const std::shared_ptr<SipMessage>& data, int retryAfterSeconds);
	static constexpr int kLockedArpMissRetrySeconds = 5;

	// ── Adopted-device registry ───────────────────────────────────────────────
	void loadDevices();   // boot-time NVS reload; runs single-threaded pre-dispatch
	// Mark a device online/offline after a (de)registration. Online state is
	// volatile registration state — never persisted. No-op if the MAC isn't
	// adopted (e.g. a Learn REGISTER whose ARP lookup missed never records).
	void markOnline(const std::string& mac, bool online);
	// Promote a device to Secured (MAC-locked + digest-enforced). Accepts a
	// 12-hex MAC or an extension. Returns true if a record actually changed.
	bool secure(const std::string& macOrExt);
	// Forget a device entirely (a later REGISTER re-learns it in Learn mode).
	// Accepts a MAC or an extension. Returns true if a record was removed.
	bool forget(const std::string& macOrExt);
	// #515: forget every Learned device in one step (one NVS write); Secured
	// devices are kept. Returns how many were removed.
	size_t forgetLearned();
	// Current registry contents (MAC-sorted by map order) for the dashboard
	// snapshot mirror.
	std::vector<AdoptedDevice> adoptedDevices() const;
	// True if any adopted device holding `ext` has been promoted to Secured
	// (issue #505: Learn mode then authenticates that extension's calls too).
	bool isExtensionSecured(std::string_view ext) const;   // no allocation on the INVITE path
	// If `mac` (12 lowercase hex) is an adopted device, sets `ext` to a view of
	// its stored extension (valid while the caller holds _mutex and the table
	// is unchanged) and returns true. No allocation: the PnP responder asks
	// this per discovery datagram (#826).
	bool extensionOf(std::string_view mac, std::string_view& ext) const;

	// ── Zero-touch assignment (#826 part B) ───────────────────────────────────
	// An admin opens a window (memory only: a reboot closes it) over a range of
	// extensions. While it is open, a config fetch from an unknown MAC may be
	// handed the next free extension in the range. The new row is LOCKED, so
	// lockedElsewhere() reserves the extension for that MAC, and ASSIGNED
	// (unclaimed) until the MAC first registers (markOnline). An unclaimed row
	// is evictable, ahead of every other row, and at most kMaxUnclaimed exist:
	// unauthenticated fetches cannot fill the table with rows nothing may evict.
	// The adoption token bucket (#515) is shared with admitLearn().
	static constexpr uint32_t kMaxAssignSpan = 500;               // hi - lo, exclusive
	static constexpr std::size_t kMaxUnclaimed = kAdoptBurst;
	struct AssignWindow
	{
		bool open = false;
		uint32_t lo = 0;
		uint32_t hi = 0;
		std::chrono::steady_clock::time_point until{};
	};
	// False (window unchanged) unless lo <= hi and hi - lo < kMaxAssignSpan.
	bool openAssignWindow(uint32_t lo, uint32_t hi, std::chrono::steady_clock::time_point until);
	void closeAssignWindow() { _assign = AssignWindow{}; }
	// The window as of `now`: reported closed once `now` reaches its end.
	AssignWindow assignWindow(std::chrono::steady_clock::time_point now) const;
	std::size_t unclaimedCount() const;
	// `mac` already has a row: its extension, true, nothing spent. Otherwise,
	// with the window open, fewer than kMaxUnclaimed unclaimed rows, room in
	// the table (or an evictable row), an adoption token and a free extension:
	// a new assigned row, true. Otherwise false and nothing changed -- in
	// particular a refusal for want of a token evicts nothing (#487 order:
	// the victim is chosen first, erased only once the token is spent).
	// `unusable(ext)` reports an extension taken outside the table (a live
	// registration, or routing that would shadow it).
	bool assignNext(const std::string& mac, std::chrono::steady_clock::time_point now,
		FunctionRef<bool(const std::string&)> unusable, std::string& outExt);
	// Would assignNext() give `mac` an extension right now? No side effects.
	bool canAssign(const std::string& mac, std::chrono::steady_clock::time_point now,
		FunctionRef<bool(const std::string&)> unusable) const;

	// Persisted row flags, the 4th field of the "devices" blob: bit 0 locked,
	// bit 1 shared, bit 2 assigned (#826). Pure, so the layout is host-tested.
	// Firmware older than #826 reads bits 0-1 only: a downgrade keeps an
	// unclaimed row as a plain locked one.
	struct RowFlags
	{
		bool locked = false;
		bool shared = false;
		bool assigned = false;
	};
	static int encodeRowFlags(const RowFlags& f);
	static RowFlags decodeRowFlags(int flags);

	// Test-only seam: directly adopt a device without an ARP lookup.
	void adoptDeviceForTest(const std::string& mac, const std::string& ext, DeviceState state = DeviceState::Learned,
		bool locked = false)
	{
		DeviceRecord r;
		r.extension = ext;
		r.state = state;
		r.online = true;
		r.locked = locked;
		r.seq = _nextSeq++;
		_devices[mac] = r;
	}

	// What moved in the registry since the last consume. Online is by far the
	// most frequent (every registration and every lease expiry flips it, and a
	// post-reboot storm flips it once per phone) and is the only kind that needs
	// no new strings in the mirror — separating it keeps that case off the
	// allocating path.
	enum class Change : uint8_t
	{
		None = 0,
		OnlineOnly,   // only volatile online flags moved; row set is unchanged
		Structural,   // a device was adopted / re-extensioned / secured / forgotten
	};
	// Report (and reset) what changed since the last call. Structural outranks
	// OnlineOnly when both happened in the same pass.
	Change consumeDevicesChange();
	// Refresh just the online flags of an already-mirrored row set, matched by
	// MAC. No allocation: the mac/extension strings in `rows` are left alone.
	void copyOnlineFlagsInto(std::vector<AdoptedDevice>& rows) const;

private:
	struct DeviceRecord
	{
		std::string extension;
		DeviceState state = DeviceState::Learned;
		bool online = false;   // volatile; not persisted
		bool locked = false;   // #440: extension bound to this MAC (persisted)
		bool shared = false;   // #440: MAC seen with >1 extension; never locks (persisted)
		uint32_t seq = 0;      // #440: adoption order, for eviction (persisted)
		bool assigned = false; // #826: zero-touch row, not yet registered by its MAC (persisted)
	};

	bool persistMode();   // false (and logged at ERROR) if any NVS step failed
	bool persistDevices();   // false (and logged at error) if any NVS step failed
	// #440: the entry to forget when a new MAC needs room at POCKETDIAL_MAX_CLIENTS:
	// an unclaimed zero-touch row first (#826), else the OLDEST plain Learned
	// entry (offline ones first). Never a claimed locked or a Secured device;
	// end() when there is none.
	std::unordered_map<std::string, DeviceRecord>::iterator oldestEvictable();
	bool hasEvictable() const;
	// #826: the #515 bucket, for assignNext() (admitLearn() keeps its own
	// inline copy of the same arithmetic).
	uint8_t adoptTokensAt(std::chrono::steady_clock::time_point now) const;
	bool takeAdoptToken(std::chrono::steady_clock::time_point now);
	bool pickFreeExtension(std::chrono::steady_clock::time_point now,
		FunctionRef<bool(const std::string&)> unusable, std::string& out) const;
	AssignWindow _assign;
	uint32_t _nextSeq = 1;
	// Find a record by MAC key or, failing that, by adopted extension.
	std::unordered_map<std::string, DeviceRecord>::iterator findDevice(const std::string& macOrExt);

	PbxEnv& _env;
	std::atomic<Mode> _mode;
	// Adopted devices keyed by 12-hex MAC. Bounded by POCKETDIAL_MAX_CLIENTS (a
	// flood of distinct MACs cannot grow the heap without limit). NVS-persisted
	// (namespace "pbxcfg", key "devices") minus the volatile online flags.
	std::unordered_map<std::string, DeviceRecord> _devices;
	Change _devicesChanged = Change::None;

	// #515: token bucket on new adoptions. Each is one persistDevices() NVS
	// write, and a host answering ARP for many fake MACs could otherwise fill
	// the table (and wear flash) in one burst. A full bucket banks nothing.
	uint8_t _adoptTokens = kAdoptBurst;
	std::chrono::steady_clock::time_point _adoptRefillAt{};
	// The refusal path IS the flood path: log at most once per refill period
	// (each log line allocates on the SIP task, #284).
	std::chrono::steady_clock::time_point _adoptLimitLoggedAt{};

	// Issue #525: digest replay limit. Nonces are stateless (HMAC-tagged, 5 min,
	// SipDigest.hpp), so without this one captured Authorization could be sent
	// again for the nonce's whole lifetime. Each nonce that has authenticated a
	// request remembers the highest nc it was used with; a request must present
	// a HIGHER nc (RFC 2617 §3.2.2) or it is re-challenged. Fixed size, no heap:
	// when full, the entry that expires first is reused. Only a request that
	// already passed verify() is recorded, so filling the table takes valid
	// credentials. Touched only under RequestsHandler's _mutex (SIP thread).
	//
	// #525 review: evicting a LIVE entry would let that nonce be replayed once
	// more, as an unknown nonce. So every eviction of a live entry raises a
	// watermark of nonce issue times (the timestamp our nonces carry,
	// SipDigest.hpp), and an unknown nonce issued at or before it is
	// re-challenged instead of trusted. Evicting the oldest-issued entry keeps
	// the watermark, and so those extra challenges, as low as possible.
	struct NonceUse
	{
		char nonce[64] = {};
		uint32_t nc = 0;
		uint64_t issuedMs = 0;   // from the nonce itself
		std::chrono::steady_clock::time_point until{};
	};
	static constexpr size_t kNonceUses = 32;
	std::array<NonceUse, kNonceUses> _nonceUses{};
	uint64_t _nonceEvictedIssuedMs = 0;   // watermark; see above
	uint32_t _nonceLiveEvictions = 0;     // how often the table overflowed
	// True if (nonce, nc) is new, and records it; false if it is a replay (an nc
	// not above the highest already accepted for this nonce).
	bool noteNonceUse(const std::string& nonce, uint32_t nc, std::chrono::steady_clock::time_point now);
public:
	// #525 review: live entries evicted since boot (table overflow). Non-zero
	// means more than kNonceUses nonces authenticated within one nonce lifetime.
	uint32_t nonceLiveEvictions() const { return _nonceLiveEvictions; }
private:
	// Raise the pending change to at least `kind` (Structural is sticky).
	void noteChange(Change kind);
};

#endif
