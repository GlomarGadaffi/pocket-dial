#ifndef SDP_OFFER_ANSWER_HPP
#define SDP_OFFER_ANSWER_HPP

// RFC 3264 offer/answer on top of the sdp:: model (issue #196).
//
// Three jobs, all pure functions over parsed Sessions:
//   buildAnswer()     -- construct the PBX's own answer to a phone's offer when
//                        the board IS the far end (440/555/777/888, voicemail),
//                        instead of echoing a PCMU-only body regardless of what
//                        was offered.
//   validateAnswer()  -- the admission check for a RELAYED answer: does this
//                        200 OK body answer THAT offer? Until now the callee's
//                        200 OK was relayed unread while the caller's INVITE
//                        was gated with a 488 (issue #196 item 5).
//   holdRequested()   -- RFC 3264 §8.4 hold plus the RFC 2543 c=0.0.0.0 form,
//                        for onReinvite()/onUpdate() to decide Held vs Connected.
//
// Same discipline as Sdp.hpp: no heap on the decision path (buildAnswer's only
// allocation is the output string), fixed capacities, no recursion.

#include <cstdint>
#include <string>
#include <string_view>

#include "Sdp.hpp"

namespace sdp
{
	// What the board can terminate itself. Order is preference order, used only
	// when the offer has no preference we can honour (RFC 3264 §6.1 lets the
	// answerer list codecs in its own preference order; we keep the OFFER's order
	// so the phone's first choice wins whenever it is one we speak).
	struct LocalCaps
	{
		uint8_t audioPts[8] = {0};          // static PTs: 0 PCMU, 8 PCMA, 9 G722
		uint8_t audioCount = 1;             // PCMU-only is what every media object speaks today
		bool    acceptTelephoneEvent = true;
		static LocalCaps pcmuOnly() { return LocalCaps{}; }
	};

	struct AnswerParams
	{
		const char* localIp = nullptr;      // o= / c= address
		uint32_t    audioPort = 0;          // where the board receives (0 == we reject audio too)
		Direction   want = Direction::SendRecv;   // the most the board will do; complemented against the offer
		uint16_t    ptime = 0;              // echo of the offer's ptime when non-zero and the board supports it
	};

	struct AnswerResult
	{
		bool acceptedAudio = false;         // at least one audio stream answered with a non-zero port
		int  audioIndex = -1;               // which m= that was (offer order)
		int  telephoneEventPt = -1;         // the PT echoed for DTMF, -1 if none
		Direction dir = Direction::None;    // the direction actually answered on that stream
	};

	// Build an answer to `offer` (parsed from `offerBody`). RFC 3264 §6: one m=
	// per offered m=, same order; a stream we cannot accept (non-audio, or no
	// codec in common) is answered with port 0 and its offered proto and first
	// format, never omitted. §6.1: answered formats are the intersection of the
	// offer with `caps`, in the OFFER's order; telephone-event is echoed with the
	// offer's dynamic PT, rtpmap and fmtp. Direction is the complement of the
	// offer's effective direction (sendonly -> recvonly, recvonly -> sendonly,
	// inactive -> inactive) further limited by `params.want`. The caller decides
	// what to do when `acceptedAudio` is false (a 488 today).
	AnswerResult buildAnswer(std::string_view offerBody, const Session& offer,
	                         const LocalCaps& caps, const AnswerParams& params,
	                         std::string& out);

	enum class AnswerVerdict : uint8_t
	{
		Ok,
		MediaCountMismatch,   // §6: the answer MUST have exactly as many m= as the offer
		MediaTypeMismatch,    // §6: same order, same media types
		FormatNotOffered,     // §6.1: an accepted stream lists a PT the offer did not
		ProtoMismatch,        // §6: transport protocol must match the offer's
		NoMedia,              // neither side described any stream
	};
	const char* answerVerdictText(AnswerVerdict v);

	// Is `answer` a valid RFC 3264 answer to `offer`? Port-0 (rejected) streams
	// are skipped for the format check but still counted and type-matched.
	AnswerVerdict validateAnswer(const Session& offer, const Session& answer);

	// True when the first audio stream (or, with none, the first stream) is on
	// hold: effective direction sendonly/inactive, or effective c= 0.0.0.0.
	bool holdRequested(std::string_view body, const Session& s);

	// Direction the answerer takes against an offered direction, limited by what
	// the answerer wants (RFC 3264 §6.1 table).
	Direction answerDirection(Direction offered, Direction want);
}

#endif
