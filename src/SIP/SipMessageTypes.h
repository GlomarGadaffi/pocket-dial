#ifndef SIP_MESSAGE_TYPES_H
#define SIP_MESSAGE_TYPES_H

class SipMessageTypes
{
public:
	SipMessageTypes() = delete;

	static constexpr auto REGISTER           = "REGISTER";
	static constexpr auto INVITE             = "INVITE";
	static constexpr auto CANCEL             = "CANCEL";
	static constexpr auto REQUEST_TERMINATED = "SIP/2.0 487 Request Terminated";
	static constexpr auto TRYING             = "SIP/2.0 100 Trying";
	static constexpr auto RINGING            = "SIP/2.0 180 Ringing";
	static constexpr auto BUSY               = "SIP/2.0 486 Busy Here";
	static constexpr auto UNAVAILABLE        = "SIP/2.0 480 Temporarily Unavailable";
	static constexpr auto OK                 = "SIP/2.0 200 OK";
	static constexpr auto ACK                = "ACK";
	// Dispatch key (never a wire start line): every non-2xx final response that
	// has no more specific key above is routed here, so it reaches a handler at
	// all instead of falling off the table unacknowledged. See
	// RequestsHandler::onFinalFailure.
	static constexpr auto FINAL_FAILURE      = "final-failure";
	static constexpr auto BYE                = "BYE";
	static constexpr auto OPTIONS            = "OPTIONS";
	// Blind transfer (RFC 3515). REFER carries a Refer-To target; the transferor
	// is acknowledged with 202 Accepted and progress is reported back via NOTIFY.
	static constexpr auto REFER              = "REFER";
	static constexpr auto NOTIFY             = "NOTIFY";
	// Instant message (RFC 3428). Inbound MESSAGEs (delivery receipts / IMs) are
	// acked with 200 OK for hygiene; the server never originates a MESSAGE.
	static constexpr auto MESSAGE            = "MESSAGE";
	static constexpr auto NOT_FOUND          = "SIP/2.0 404 Not Found";
	static constexpr auto BAD_REQUEST        = "SIP/2.0 400 Bad Request";
	static constexpr auto ACCEPTED           = "SIP/2.0 202 Accepted";
	// RFC 3311 mid-dialog media renegotiation / session-timer keep-alive.
	static constexpr auto UPDATE             = "UPDATE";
	// RFC 6665 event-subscription requests (BLF / presence).
	static constexpr auto SUBSCRIBE          = "SUBSCRIBE";
	// 489 Bad Event — returned when the requested event package is not supported.
	static constexpr auto BAD_EVENT          = "SIP/2.0 489 Bad Event";
};

#endif
