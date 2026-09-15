#include "SipSdpMessage.hpp"
#include "Sdp.hpp"
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <cctype>

SipSdpMessage::SipSdpMessage(const std::string& message, sockaddr_in src) : SipMessage(message, src)
{
}

SipSdpMessage& SipSdpMessage::operator=(const SipSdpMessage& other)
{
	if (this == &other) return *this;

	SipMessage::operator=(other);   // copies the body, advances _bodyGen
	// Deliberately NOT copying _spans/_spansGen — see the header. Generation 0
	// is never a live body generation, so this forces a re-parse on next access.
	_spansGen = 0;
	return *this;
}

void SipSdpMessage::setMedia(std::string value)
{
	// Operate on a local copy of the body so the search offset and the mutation
	// stay consistent within the same buffer (no cross-object pointer math
	// against the base class's storage).
	std::string body(getBody());
	size_t pos_start = 0;
	while (pos_start < body.size())
	{
		size_t pos_end = body.find("\r\n", pos_start);
		size_t next_start = pos_end + 2;
		if (pos_end == std::string::npos)
		{
			pos_end = body.find('\n', pos_start);
			next_start = pos_end + 1;
		}
		size_t lineLen = (pos_end == std::string::npos) ? (body.size() - pos_start) : (pos_end - pos_start);

		if (lineLen >= 2 && body.compare(pos_start, 2, "m=") == 0)
		{
			body.replace(pos_start, lineLen, value);
			setBody(body);
			return;
		}
		pos_start = (pos_end == std::string::npos) ? body.size() : next_start;
	}
	// No "m=" line found: no-op, matching the original's behavior when there
	// was no media line to replace.
}

// Issue #101(B): one single-pass parse of the body, cached until the body
// changes. Line splitting tolerates CRLF and bare LF alike, as every decoder
// here does.
// Issue #196: the cache is derived from the sdp:: model. One flat, bounded pass
// (sdp::parse honours SdpLimits::kMaxLines and its own fixed capacities -- the
// CWE-674 discipline this class has always carried, see the header), into the
// engine-owned scratch Session, then the six spans are copied out as offsets.
// The model is NOT kept: at ~1.7 KB it would multiply by the pool size.
const SipSdpMessage::SdpSpans& SipSdpMessage::ensureParsed() const
{
	const uint64_t gen = bodyGeneration();
	if (_spansGen == gen)
	{
		return _spans;   // body has not been touched since the last parse
	}

	const std::string_view body = getBody();

	// Rebuilt from scratch rather than updated in place: a field present in the
	// PREVIOUS body and absent from this one must not survive in the cache. This
	// is the recycled-pool-slot case (reset() hands the same object back out with
	// a different call's SDP), which is precisely what makes a stale cache here
	// dangerous rather than merely wrong. sdp::parse() resets its output for the
	// same reason.
	sdp::Session& s = sdp::scratch(0);
	sdp::parse(body, s);

	auto toField = [](sdp::Span sp) { return FieldSpan{sp.pos, sp.len}; };

	SdpSpans spans;
	spans.version     = toField(s.version);
	spans.originator  = toField(s.origin);
	spans.sessionName = toField(s.name);
	spans.time        = toField(s.time);

	// The stream this PBX cares about is the first AUDIO one (RFC 8866 lets an
	// offer lead with video, which the six-field scanner misread as "the" media
	// line). With no audio section fall back to the first section of any type so
	// a non-audio-only body still reports something; with no m= at all, absent.
	int idx = s.firstAudio();
	if (idx < 0 && s.mediaCount > 0) idx = 0;
	if (idx >= 0)
	{
		const unsigned i = static_cast<unsigned>(idx);
		spans.media                 = toField(s.media[i].line);
		spans.rtpPort               = static_cast<int>(s.media[i].port);
		spans.connectionInformation = toField(sdp::effectiveConnection(s, i));   // media-level c= wins
	}
	else
	{
		spans.connectionInformation = toField(s.connection);
	}

	_spans    = spans;
	_spansGen = gen;
	return _spans;
}

std::string_view SipSdpMessage::viewOf(const FieldSpan& span) const
{
	if (span.len == 0) return {};   // field absent — same empty view as before

	// Belt-and-braces: ensureParsed() guarantees the span indexes the body it was
	// parsed from, so an out-of-range span means the generation counter missed a
	// mutation. Report the field absent rather than let substr() throw
	// std::out_of_range out of the middle of a SIP handler — exceptions are
	// enabled in the ESP-IDF build (CONFIG_COMPILER_CXX_EXCEPTIONS=y) but nothing
	// up the call stack catches, so the throw would take the SIP task with it.
	// The invariant is still enforced by the tests, not by this clamp.
	const std::string_view body = getBody();
	if (span.pos > body.size() || span.len > body.size() - span.pos) return {};
	return body.substr(span.pos, span.len);
}

std::string_view SipSdpMessage::getVersion() const
{
	return viewOf(ensureParsed().version);
}

std::string_view SipSdpMessage::getOriginator() const
{
	return viewOf(ensureParsed().originator);
}

std::string_view SipSdpMessage::getSessionName() const
{
	return viewOf(ensureParsed().sessionName);
}

std::string_view SipSdpMessage::getConnectionInformation() const
{
	return viewOf(ensureParsed().connectionInformation);
}

std::string_view SipSdpMessage::getTime() const
{
	return viewOf(ensureParsed().time);
}

std::string_view SipSdpMessage::getMedia() const
{
	return viewOf(ensureParsed().media);
}

int SipSdpMessage::getRtpPort() const
{
	// Already decoded by the model (bounded to 65535 there); the old
	// extractRtpPort() re-scan of the m= line is gone with the scanner.
	return ensureParsed().rtpPort;
}
