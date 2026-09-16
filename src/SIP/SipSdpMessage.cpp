#include "SipSdpMessage.hpp"

#include <cctype>
#include <cstring>
#include <string>

SipSdpMessage::SipSdpMessage(const std::string& message, sockaddr_in src) : SipMessage(message, src)
{
}

SipSdpMessage& SipSdpMessage::operator=(const SipSdpMessage& other)
{
	if (this == &other) return *this;

	SipMessage::operator=(other);   // copies the body, advances _bodyGen
	// Deliberately NOT copying the cache state — see the header. Generation 0 is
	// never a live body generation, so this forces a re-parse on next access.
	// The slot hint is cleared too: keeping it would point this message at a
	// slot owned by `other`, and while ensureParsed() would catch that via the
	// owner check, leaving a knowingly-wrong hint behind is worse than clearing
	// it.
	_spansGen = 0;
	_slot     = 0xFF;
	return *this;
}

// ── Shared scratch ───────────────────────────────────────────────────────────
//
// Two slots, file-static, tagged with (owner, generation). See the header for
// why the model does not live in the message and what makes sharing safe.
namespace
{
	constexpr uint8_t kScratchSlots = 2;

	struct ScratchSlot
	{
		const SipSdpMessage* owner = nullptr;
		uint64_t             gen   = 0;
		sdp::Session         model{};
	};

	ScratchSlot g_scratch[kScratchSlots];

	// Round-robin eviction. Deliberately not true LRU: with two slots the two
	// differ only when the same message is read twice in a row, which the
	// generation check already short-circuits before eviction is reached. A
	// counter is cheaper and has no tie-breaking behaviour to get wrong.
	uint8_t g_nextSlot = 0;
}

const sdp::Session& SipSdpMessage::ensureParsed() const
{
	const uint64_t gen = bodyGeneration();

	// Fast path: my own cache generation agrees with my body AND the slot I
	// remember is still genuinely mine.
	//
	// All three conditions are load-bearing. _spansGen catches a body mutation.
	// The owner check catches a slot that has been evicted and re-used by
	// another message, and also catches a COPY that inherited my hint — a copy
	// is a different object at a different address, so it can never pass this.
	// The slot's own gen check is belt-and-braces against a pooled object being
	// destroyed and a new one landing at the same address.
	//
	// ON ADDRESS REUSE (ABA), because it is the case a reader will worry about:
	// the heap-fallback path deletes and re-allocates SipSdpMessage, so a NEW
	// object really can land on an address a scratch slot is still tagged with.
	// It is safe, but only because of the ORDER below. `_spansGen == gen` is
	// checked FIRST and is per-object state: it can only be true if THIS object
	// performed that parse, and that parse is what wrote its own tag into the
	// slot. A fresh object starts at _spansGen = 0, and operator= resets it, so
	// neither can ever take the fast path on an inherited tag.
	//
	// So: do NOT reorder these, and do NOT let the tag check alone be sufficient.
	// Either change opens the ABA case that the current ordering closes.
	if (_spansGen == gen && _slot < kScratchSlots
		&& g_scratch[_slot].owner == this
		&& g_scratch[_slot].gen == gen)
	{
		return g_scratch[_slot].model;
	}

	// Prefer a slot that is already nominally mine, so re-parsing after a body
	// mutation does not evict the OTHER message being read alongside this one.
	uint8_t slot = kScratchSlots;
	for (uint8_t i = 0; i < kScratchSlots; ++i)
	{
		if (g_scratch[i].owner == this) { slot = i; break; }
	}
	if (slot == kScratchSlots)
	{
		slot = g_nextSlot;
		g_nextSlot = static_cast<uint8_t>((g_nextSlot + 1) % kScratchSlots);
	}

	ScratchSlot& s = g_scratch[slot];

	// parse() resets the model before filling it, so a field from the PREVIOUS
	// occupant of this slot cannot survive into ours.
	//
	// A non-Ok verdict leaves `model` as the reset-but-empty state, which is the
	// right answer for an accessor: every field reads absent. The wire path
	// refuses such a body with a 488 long before it reaches here (checkSdp()),
	// so this only arises for a locally built or test-constructed message, where
	// "the body is not usable, report nothing" beats both throwing and
	// returning half a parse.
	(void)sdp::parse(getBody(), s.model);

	s.owner   = this;
	s.gen     = gen;
	_slot     = slot;
	_spansGen = gen;
	return s.model;
}

// ── The six legacy accessors, reimplemented on the model ─────────────────────
//
// Each returns the WHOLE line including its two-character prefix, exactly as
// before — see the span convention in Sdp.hpp, which exists largely so these
// stay byte-identical for their existing callers. The string_views point into
// the body, not into the scratch slot, so they remain valid after the slot is
// evicted.

std::string_view SipSdpMessage::getVersion() const
{
	return sdp::view(getBody(), ensureParsed().version);
}

std::string_view SipSdpMessage::getOriginator() const
{
	return sdp::view(getBody(), ensureParsed().origin);
}

std::string_view SipSdpMessage::getSessionName() const
{
	return sdp::view(getBody(), ensureParsed().name);
}

std::string_view SipSdpMessage::getConnectionInformation() const
{
	// CORRECTION TO THE RECORD, because issue #196 item 2 overstates this and the
	// overstatement nearly got baked in here. Item 2 says a phone emitting c=
	// only per-media "defeats getConnectionInformation() outright". It does not.
	// The parser this replaces scanned for ANY line starting with "c=", session
	// or media level, last one wins — so it found a media-level c= perfectly
	// well. (Same shape as the #199 finding: an issue calling something absent
	// when it is present but unreachable by a different route.)
	//
	// The real defect is narrower and still real: the old scan had no notion of
	// WHICH section a c= belonged to, so on a multi-section body there was no way
	// to ask for a particular stream's address — you got whichever c= came last.
	// That is what the model fixes, via effectiveConnection(s, i).
	//
	// This accessor deliberately reproduces the OLD semantics exactly, because
	// the brief for this branch is that no caller outside this class changes:
	// walk sections backwards for the last media-level c=, else fall back to the
	// session's. For any body that respects RFC 8866's line ordering (session c=
	// precedes the first m=), that is identical to "last c= line in the body".
	// Callers that want a specific section's address use the model directly.
	const sdp::Session& s = ensureParsed();
	for (int i = static_cast<int>(s.nMedia) - 1; i >= 0; --i)
	{
		if (!s.media[i].connection.absent())
		{
			return sdp::view(getBody(), s.media[i].connection);
		}
	}
	return sdp::view(getBody(), s.connection);
}

std::string_view SipSdpMessage::getTime() const
{
	return sdp::view(getBody(), ensureParsed().time);
}

std::string_view SipSdpMessage::getMedia() const
{
	// The LAST media section's m= line, not the first.
	//
	// This looks wrong and is not. The parser this replaces had a single media
	// span overwritten by every m= line it met, so a body with two m= lines
	// reported the SECOND one, and SipSdpMessage_cache_test pins exactly that
	// ("last-one-wins on a repeated field"). Returning media[0] here is the
	// intuitive reading of a sectioned model and it broke that test immediately.
	//
	// Preserving the old answer is the right call for this branch: the brief is
	// that no caller outside this class changes behaviour, and getMedia() feeds
	// getRtpPort(), which feeds RequestsHandler::parseCallerRtp. Quietly moving
	// which stream the PBX aims RTP at, inside a parser refactor, is precisely
	// the kind of change that should not ride along unannounced.
	//
	// It IS wrong for a genuine audio+video offer — it returns the video line —
	// but it was equally wrong before, and fixing it means teaching the callers
	// about sections. Tracked as #253, which argues the fix is explicit section
	// selection at the call sites ("the first AUDIO section"), not media[0].
	const sdp::Session& s = ensureParsed();
	if (s.nMedia == 0) return std::string_view();
	return sdp::view(getBody(), s.media[s.nMedia - 1].line);
}

int SipSdpMessage::getRtpPort() const
{
	// Deliberately still parsed out of the m= line text rather than read from
	// Media::port, so this returns bit-for-bit what it always has — including
	// its saturation behaviour on absurd input. Switching to the model's parsed
	// port would be a behaviour change smuggled into a refactor; it belongs in
	// the follow-up that migrates callers, not here.
	return extractRtpPort(getMedia());
}

bool SipSdpMessage::isHoldOffer() const
{
	// #253: the section a call site means must be picked explicitly, never
	// implied by index 0. The first AUDIO section is the one hold applies to
	// here; fall back to session-level-only direction/connection when the
	// offer has no audio section at all -- either because it truly has no
	// media sections (nMedia == 0, which a body that fails to parse also
	// lands on), or because it has media sections and none of them are
	// audio (e.g. video-only). Both cases use the SAME sentinel: an index
	// equal to nMedia is guaranteed out of range, so effectiveDirection()/
	// effectiveConnection()'s own `mediaIndex < s.nMedia` guards fall
	// through to session level for either reason, uniformly.
	//
	// Issue #281: this used to initialize audioSection to 0 and only
	// overwrite it on a match, so "media sections exist but none are audio"
	// silently read section 0 -- whatever type it actually was -- instead of
	// falling back to session level as this comment already claimed.
	const sdp::Session& s = ensureParsed();
	unsigned audioSection = s.nMedia;
	for (uint8_t i = 0; i < s.nMedia; ++i)
	{
		if (sdp::view(getBody(), s.media[i].typeName) == "audio")
		{
			audioSection = i;
			break;
		}
	}
	return sdp::isHold(s, getBody(), audioSection);
}

void SipSdpMessage::setMedia(std::string value)
{
	// Replace the first m= line, using the model to find it instead of
	// re-scanning the body by hand.
	//
	// setBody() bumps _bodyGen, so the next accessor re-parses against the NEW
	// bytes: the model can never be left describing a body that no longer
	// exists. That ordering is the whole safety argument for mutation here.
	// NOTE THE ASYMMETRY WITH getMedia(), which is pre-existing and preserved:
	// the old getMedia() reported the LAST m= line (a single span overwritten
	// by each one), while the old setMedia() replaced the FIRST (it returned
	// on first match). So on a two-section body they disagree about which
	// line they mean. That is a real inconsistency, it predates this change,
	// and reproducing it exactly is deliberate -- silently aligning them here
	// would change behaviour for any caller relying on either. Tracked as #253.
	const sdp::Session& s = ensureParsed();
	if (s.nMedia == 0) return;   // no m= line to replace — same no-op as before

	const sdp::Span line = s.media[0].line;
	std::string body(getBody());
	if (line.pos > body.size() || line.len > body.size() - line.pos) return;

	body.replace(line.pos, line.len, value);
	setBody(body);
}

int SipSdpMessage::extractRtpPort(std::string_view data) const
{
	auto spacePos = data.find(' ');
	if (spacePos == std::string_view::npos)
		return 0;
	size_t portStart = spacePos + 1;
	while (portStart < data.size() && std::isspace(static_cast<unsigned char>(data[portStart]))) ++portStart;
	size_t portEnd = portStart;
	while (portEnd < data.size() && std::isdigit(static_cast<unsigned char>(data[portEnd]))) ++portEnd;
	if (portEnd == portStart)
		return 0;
	int val = 0;
	for (size_t i = portStart; i < portEnd; ++i)
	{
		if (val > 200000000) return 200000000;
		val = val * 10 + (data[i] - '0');
	}
	return val;
}
