#include "SdpOfferAnswer.hpp"

#include <string>

namespace sdp
{
	namespace
	{
		bool capsAccept(const LocalCaps& caps, uint8_t pt)
		{
			for (unsigned k = 0; k < caps.audioCount && k < 8; ++k)
				if (caps.audioPts[k] == pt) return true;
			return false;
		}

		// Static-PT encoding names (RFC 3551 §6) for the codecs the board can
		// terminate. A static PT needs no a=rtpmap, but emitting one is harmless
		// and matches what buildMediaSdp() always did for PCMU.
		const char* staticEncoding(uint8_t pt)
		{
			switch (pt)
			{
				case 0: return "PCMU";
				case 8: return "PCMA";
				case 9: return "G722";
				default: return nullptr;
			}
		}

		// Copy a body span into a small fixed buffer so the writer can take a
		// const char*. Bounded by the buffer; longer values are truncated, which
		// for an fmtp we echo back is the safe direction (never longer than
		// offered).
		struct SmallBuf
		{
			// 40 bytes covers every value this echoes (a telephone-event fmtp
			// like "0-16", a proto like "RTP/SAVPF", a media type). Sized for the
			// 8 KB task stack, not for generality: nine of these live in
			// buildAnswer()'s frame.
			char b[40] = {};
			const char* set(std::string_view v)
			{
				const size_t n = v.size() < sizeof(b) - 1 ? v.size() : sizeof(b) - 1;
				for (size_t i = 0; i < n; ++i) b[i] = v[i];
				b[n] = 0;
				return b;
			}
		};
	}

	Direction answerDirection(Direction offered, Direction want)
	{
		// RFC 3264 §6.1: offered sendonly -> answer recvonly; recvonly -> sendonly;
		// inactive -> inactive; sendrecv -> whatever the answerer wants.
		Direction complement;
		switch (offered)
		{
			case Direction::SendOnly: complement = Direction::RecvOnly; break;
			case Direction::RecvOnly: complement = Direction::SendOnly; break;
			case Direction::Inactive: return Direction::Inactive;
			default:                  complement = Direction::SendRecv; break;
		}
		if (want == Direction::Inactive) return Direction::Inactive;
		if (want == Direction::SendRecv) return complement;
		// The answerer wants one direction only: intersect with the complement.
		if (complement == Direction::SendRecv) return want;
		return complement == want ? want : Direction::Inactive;
	}

	AnswerResult buildAnswer(std::string_view offerBody, const Session& offer,
	                         const LocalCaps& caps, const AnswerParams& params,
	                         std::string& out)
	{
		AnswerResult res;
		SessionSpec spec;
		spec.originAddr = params.localIp;

		// Per-media echo buffers for the telephone-event fmtp values (one per
		// possible m=; the writer reads them after this loop, so they must
		// outlive it).
		SmallBuf fmtpBuf[Limits::kMaxMedia];
		SmallBuf protoBuf[Limits::kMaxMedia];
		SmallBuf typeBuf[Limits::kMaxMedia];

		for (unsigned i = 0; i < offer.mediaCount; ++i)
		{
			const Media& om = offer.media[i];
			MediaSpec* am = spec.addMedia();
			if (!am) break;   // cannot happen: both sides share Limits::kMaxMedia

			am->type  = typeBuf[i].set(view(offerBody, om.typeName));
			am->proto = protoBuf[i].set(view(offerBody, om.proto));

			const bool weCanTerminate = (om.type == MediaType::Audio) && !res.acceptedAudio &&
			                            params.audioPort != 0 && om.port != 0;
			if (weCanTerminate)
			{
				// Intersection in the OFFER's order (§6.1), then the DTMF PT.
				for (unsigned k = 0; k < om.fmtCount; ++k)
				{
					const uint8_t pt = om.fmt[k];
					if (!capsAccept(caps, pt)) continue;
					FormatSpec f;
					f.pt = pt;
					f.encoding = staticEncoding(pt);
					f.clock = (pt == 9) ? 8000 : 8000;   // G.722's RTP clock is 8000 by RFC 3551 quirk
					am->add(f);
				}
				const int evPt = om.telephoneEventPt();
				if (am->formatCount > 0 && caps.acceptTelephoneEvent && evPt > 0 && evPt <= 127)
				{
					FormatSpec f;
					f.pt = static_cast<uint8_t>(evPt);
					f.encoding = "telephone-event";
					const Rtpmap* r = om.findRtpmap(f.pt);
					f.clock = (r && r->clock) ? r->clock : 8000;
					// Echo the offered fmtp so we never claim events the phone did
					// not offer; fall back to the DTMF subset when it gave none.
					f.fmtp = (r && r->fmtp.present()) ? fmtpBuf[i].set(view(offerBody, r->fmtp)) : "0-15";
					am->add(f);
					res.telephoneEventPt = evPt;
				}
			}

			if (am->formatCount == 0)
			{
				// Rejected stream (§6): port 0, the offered proto, and at least one
				// of the offered formats so the m= line stays syntactically valid.
				am->port = 0;
				FormatSpec f;
				f.pt = om.fmtCount ? om.fmt[0] : 0;
				am->add(f);
				am->dir = Direction::None;
				continue;
			}

			am->port = params.audioPort;
			am->dir  = answerDirection(effectiveDirection(offer, i), params.want);
			am->ptime = params.ptime;
			res.acceptedAudio = true;
			res.audioIndex = static_cast<int>(i);
			res.dir = am->dir;
		}

		if (offer.mediaCount == 0)
		{
			// An offer with no m= (not a valid offer, but tolerated upstream): answer
			// with nothing to negotiate, same as the old builder would have.
			MediaSpec* am = spec.addMedia();
			if (am)
			{
				am->port = 0;
				FormatSpec f;
				f.pt = 0;
				am->add(f);
			}
		}

		out.clear();
		write(spec, out);
		return res;
	}

	const char* answerVerdictText(AnswerVerdict v)
	{
		switch (v)
		{
			case AnswerVerdict::Ok:                 return "ok";
			case AnswerVerdict::MediaCountMismatch: return "answer m= count differs from offer";
			case AnswerVerdict::MediaTypeMismatch:  return "answer m= order/type differs from offer";
			case AnswerVerdict::FormatNotOffered:   return "answer lists a payload type the offer did not";
			case AnswerVerdict::ProtoMismatch:      return "answer transport differs from offer";
			case AnswerVerdict::NoMedia:            return "no media described";
		}
		return "rejected";
	}

	AnswerVerdict validateAnswer(const Session& offer, const Session& answer)
	{
		if (offer.mediaCount == 0 && answer.mediaCount == 0) return AnswerVerdict::NoMedia;
		// Sections past Limits::kMaxMedia were counted, not modelled, on both
		// sides; compare the totals so an answer that drops a fourth stream is
		// still caught.
		if (offer.mediaCount + offer.droppedMedia != answer.mediaCount + answer.droppedMedia)
			return AnswerVerdict::MediaCountMismatch;
		for (unsigned i = 0; i < offer.mediaCount && i < answer.mediaCount; ++i)
		{
			const Media& o = offer.media[i];
			const Media& a = answer.media[i];
			if (o.type != a.type) return AnswerVerdict::MediaTypeMismatch;
			if (o.type == MediaType::Other && (o.typeName.len != a.typeName.len))
				return AnswerVerdict::MediaTypeMismatch;   // cannot compare names without bodies; length is the cheap guard
			if (a.port == 0) continue;   // rejected stream: formats are unconstrained (§6)
			if (o.proto.len != a.proto.len) return AnswerVerdict::ProtoMismatch;
			for (unsigned k = 0; k < a.fmtCount; ++k)
				if (!o.hasFormat(a.fmt[k])) return AnswerVerdict::FormatNotOffered;
		}
		return AnswerVerdict::Ok;
	}

	bool holdRequested(std::string_view body, const Session& s)
	{
		if (s.mediaCount == 0) return false;
		const int a = s.firstAudio();
		return isHold(body, s, a >= 0 ? static_cast<unsigned>(a) : 0u);
	}
}
