#ifndef TELEPHONY_PROVIDER_HPP
#define TELEPHONY_PROVIDER_HPP

// ── Telephony provider abstraction ────────────────────────────────────────────
// `AnchorClient` (AnchorClient.hpp) IS the provider-agnostic telephony interface:
// it carries the provider-neutral concerns only — credential init / token
// lifecycle (init/start/stop), call control (makeCall/answerCall/dropCall),
// bidirectional PCM16 8 kHz audio framing (writeAudio/registerAudioRxCallback),
// and event callbacks (Ringing/Answered/Dropped/Dtmf/Incoming). Nothing in it is
// specific to one external system. This header gives that role an explicit name
// and adds the fixed-size registry/factory that maps a configured provider TYPE
// to the concrete implementation linked into the firmware.
//
// Concrete implementations today:
//   LoopbackAnchorClient  — on-box mock (no external system), the safe default.
//   TelephonyAnchorClient — real WAN-anchor client (OAuth2 client-credentials,
//                           a call-control WebSocket, and chunked-HTTPS PCM16
//                           media streams), ported from drawbridge and
//                           registered under TelephonyProviderType::Telephony
//                           in RequestsHandler's constructor.
//   StubTelephonyProvider — honest compile-time scaffolding for a provider type
//                           that is declared in the enum but NOT implemented.
//                           Nothing uses it today (both current enumerators have
//                           a real client behind them) — it stays here as the
//                           pattern for the next declared-but-unimplemented
//                           provider type. Every call into a stub fails cleanly
//                           (start() returns false, etc.) instead of faking
//                           connectivity, and telephonyProviderImplemented()
//                           reports false for whatever type is stubbed.
//
// pocket-dial ships two real implementations today: Loopback (on-box mock,
// the safe default for local dev/testing) and Telephony (TelephonyAnchorClient,
// the real WAN-anchor client described above). To bridge a THIRD external
// system (a different SIP trunk, a recording server, an AI pipeline, another
// Telephony-style API, ...), add a TelephonyProviderType enumerator for it and
// register a real AnchorClient the same way Loopback and Telephony are
// registered.
//
// Invariants:
//   * Provider objects are constructed ONCE at boot (they are members of
//     RequestsHandler / static storage) — the registry stores raw pointers and
//     never allocates.
//   * No heap allocation in any per-packet/per-frame media path: writeAudio /
//     the audio RX callback operate on caller-owned PCM16 buffers.

#include "AnchorClient.hpp"
#include <cstdint>
#include <cstddef>

// The provider-agnostic interface, by its proper name. AnchorClient is kept as
// the primary identifier so the existing engine/tests stay untouched.
using ITelephonyProvider = AnchorClient;

// Provider types selectable from config (NVS u8 on ESP, config file on host).
// The numeric values are PERSISTED — never reorder or reuse them. Both
// enumerators below have a real implementation. This enum is also the
// extension point for your own provider (register it the same way, or add a
// StubTelephonyProvider slot if the real client isn't ready yet).
enum class TelephonyProviderType : uint8_t
{
	Loopback  = 0,  // on-box mock anchor (no external system) — implemented
	Telephony = 1,  // Telephony API call-control provider (TelephonyAnchorClient,
	                // ported from drawbridge) — implemented
	Count           // sentinel — keep last
};

// Display/log name for a provider type ("?" for out-of-range).
const char* telephonyProviderName(TelephonyProviderType t);

// True only for providers with a real, working implementation. Stubs return
// false so config/UI surfaces can be honest about what actually dials.
bool telephonyProviderImplemented(TelephonyProviderType t);

// ── Honest stub provider ─────────────────────────────────────────────────────
// Compile-time scaffolding for a declared-but-unimplemented provider. Every
// operation fails cleanly: start() returns false, isConnected() is always
// false, makeCall/answerCall/dropCall/writeAudio return false. It never fakes
// connectivity, never fires events, and never touches the network.
class StubTelephonyProvider : public AnchorClient
{
public:
	explicit StubTelephonyProvider(TelephonyProviderType type) : _type(type) {}

	bool init(const std::string&, const std::string&,
	          const std::string&, const std::string&) override { return true; }
	bool start() override { return false; }            // not implemented yet
	void stop() override {}
	bool isConnected() const override { return false; }
	bool makeCall(const std::string&, std::string* ownLegOut = nullptr) override { if (ownLegOut) ownLegOut->clear(); return false; }
	bool answerCall(const std::string&) override { return false; }
	bool dropCall(const std::string&) override { return false; }
	void setEventCallback(EventCallback) override {}   // no events will ever fire
	bool writeAudio(const std::string&, const int16_t*, size_t) override { return false; }
	void registerAudioRxCallback(AudioRxCallback) override {}
	void tick() override {}                            // no periodic maintenance

	TelephonyProviderType type() const { return _type; }

private:
	TelephonyProviderType _type;
};

// ── Fixed-size provider registry / factory ───────────────────────────────────
// Maps TelephonyProviderType → a boot-constructed provider instance. Static
// table, no dynamic plugin machinery: registration happens once during
// RequestsHandler construction, selection thereafter is a bounds-checked array
// read. select() returns nullptr for unregistered types — callers fall back to
// the loopback provider (and say so in the log).
class TelephonyProviderRegistry
{
public:
	static constexpr size_t kMaxProviders = static_cast<size_t>(TelephonyProviderType::Count);

	// false if the type is out of range, the slot is already taken, or
	// `provider` is null. Idempotent re-registration of the SAME pointer is ok.
	bool registerProvider(TelephonyProviderType t, AnchorClient* provider);

	// The provider for `t`, or nullptr if none registered / out of range.
	AnchorClient* select(TelephonyProviderType t) const;

private:
	AnchorClient* _providers[kMaxProviders] = {};
};

#endif // TELEPHONY_PROVIDER_HPP
