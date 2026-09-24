#ifndef REGISTRAR_HPP
#define REGISTRAR_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "PbxEnv.hpp"
#include "SipMessage.hpp"

// ── Registrar admission + adopted-device registry (STAGE 2) ───────────────────
// The REGISTER-side state machine extracted from RequestsHandler: runtime
// registrar policy (Open / Learn / Secure), digest challenge/verify, and the
// Learn-mode TOFU + MAC-lock adoption lifecycle with its NVS-persisted device
// table.
//
// Locking: unless noted otherwise every method assumes the caller holds the
// engine's _mutex — the same convention as the monolith this came from. The
// mode itself is atomic so getMode() stays lock-free for the dashboard.
class Registrar
{
public:
	enum class Mode : uint8_t
	{
		Open   = 0,   // standalone: accept every REGISTER, no challenge (legacy)
		Learn  = 1,   // TOFU + MAC-lock: adopt unknown devices, enforce secured ones
		Secure = 2,   // require digest auth for every provisioned extension
	};

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
	};

	enum class AuthDecision : uint8_t { Accept, Challenge, Reject };

	Registrar(PbxEnv& env, Mode defaultMode) : _env(env), _mode(defaultMode) {}

	// ── Boot-time default (issue #397) ────────────────────────────────────────
	// What mode a board boots in when NVS has no reg_mode, and whether to write
	// it back. Pure, so the host suite tests the rule the board runs.
	//   stored mode present            -> that mode, nothing written
	//   no stored mode, trusted store  -> Learn, persisted
	//   no stored mode, Uncertain store (unreadable, failed/downgrade schema)
	//                                  -> Learn, NOT persisted: re-decided next boot
	// Never Open by default (#441 review): a missing key is also what every failed
	// write looks like, so it must fail safe. A DEPLOYED pre-#397 board keeps Open
	// because the schema v1 -> v2 migration WRITES it (DeviceConfig.cpp,
	// migrateKeepPre397BoardOpen), and the v2 stamp lands only if that succeeded.
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
	// returns the digest decision. On a first-packet ARP miss returns Accept
	// (deferring the lock to the next REGISTER). Records/updates the adoption
	// entry — poll consumeDevicesChange() afterwards to mirror the snapshot.
	AuthDecision admitLearn(const std::shared_ptr<SipMessage>& data,
		const std::string& ext, std::string& outRejectReason);
	// Emit a 401 Unauthorized with a fresh WWW-Authenticate challenge. `stale`
	// answers an expired-but-valid nonce.
	void sendChallenge(const std::shared_ptr<SipMessage>& data, bool stale);
	// Emit a 403 Forbidden with a reason phrase.
	void sendForbidden(const std::shared_ptr<SipMessage>& data, const std::string& reason);

	// ── Adopted-device registry ───────────────────────────────────────────────
	void loadDevices();   // boot-time NVS reload; runs single-threaded pre-dispatch
	// Mark a device online/offline after a (de)registration. Online state is
	// volatile registration state — never persisted. No-op if the MAC isn't
	// adopted (e.g. Open mode never records).
	void markOnline(const std::string& mac, bool online);
	// Promote a device to Secured (MAC-locked + digest-enforced). Accepts a
	// 12-hex MAC or an extension. Returns true if a record actually changed.
	bool secure(const std::string& macOrExt);
	// Forget a device entirely (a later REGISTER re-learns it in Learn mode).
	// Accepts a MAC or an extension. Returns true if a record was removed.
	bool forget(const std::string& macOrExt);
	// Current registry contents (MAC-sorted by map order) for the dashboard
	// snapshot mirror.
	std::vector<AdoptedDevice> adoptedDevices() const;

	// Test-only seam: directly adopt a device without an ARP lookup.
	void adoptDeviceForTest(const std::string& mac, const std::string& ext, DeviceState state = DeviceState::Learned)
	{
		DeviceRecord r;
		r.extension = ext;
		r.state = state;
		r.online = true;
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
	};

	bool persistMode();   // false (and logged at ERROR) if any NVS step failed
	void persistDevices();
	// Find a record by MAC key or, failing that, by adopted extension.
	std::unordered_map<std::string, DeviceRecord>::iterator findDevice(const std::string& macOrExt);

	PbxEnv& _env;
	std::atomic<Mode> _mode;
	// Adopted devices keyed by 12-hex MAC. Bounded by POCKETDIAL_MAX_CLIENTS (a
	// flood of distinct MACs cannot grow the heap without limit). NVS-persisted
	// (namespace "pbxcfg", key "devices") minus the volatile online flags.
	std::unordered_map<std::string, DeviceRecord> _devices;
	Change _devicesChanged = Change::None;
	// Raise the pending change to at least `kind` (Structural is sticky).
	void noteChange(Change kind);
};

#endif
