// SipRegistrationClient.cpp — see the header for the design rationale, the
// outbox contract (this class never sends) and the credential discipline.

#include "SipRegistrationClient.hpp"

#include "IDGen.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>

namespace
{
	// Bounded copy into a fixed array. Returns false — writing NOTHING — when the
	// source would not fit. Every caller treats that as a hard error rather than
	// truncating: a truncated nonce, realm or password yields a digest the server
	// can never reproduce, and it does so with no error anywhere on the wire.
	bool copyBounded(char* dst, size_t cap, std::string_view src)
	{
		if (src.size() + 1 > cap)
		{
			return false;
		}
		std::memcpy(dst, src.data(), src.size());
		dst[src.size()] = '\0';
		return true;
	}

	void wipe(char* dst, size_t cap)
	{
		// volatile so the compiler may not elide the overwrite of a dead buffer.
		volatile char* p = dst;
		for (size_t i = 0; i < cap; ++i) p[i] = '\0';
	}

	// Parse a bare non-negative decimal. Returns false on empty input, any
	// non-digit, or overflow past `cap`. Leading/trailing whitespace is tolerated
	// because header values routinely carry it.
	bool parseUint(std::string_view sv, uint32_t cap, uint32_t& out)
	{
		size_t b = 0, e = sv.size();
		while (b < e && std::isspace(static_cast<unsigned char>(sv[b]))) ++b;
		while (e > b && std::isspace(static_cast<unsigned char>(sv[e - 1]))) --e;
		if (b >= e) return false;

		uint64_t v = 0;
		for (size_t i = b; i < e; ++i)
		{
			if (!std::isdigit(static_cast<unsigned char>(sv[i]))) return false;
			v = v * 10 + static_cast<uint64_t>(sv[i] - '0');
			if (v > cap) return false;
		}
		out = static_cast<uint32_t>(v);
		return true;
	}

	// Find ";expires=" (case-insensitive) inside one Contact entry and read it.
	bool expiresParamOf(std::string_view entry, uint32_t& out)
	{
		static const std::string_view kKey = ";expires=";
		for (size_t i = 0; i + kKey.size() <= entry.size(); ++i)
		{
			bool hit = true;
			for (size_t j = 0; j < kKey.size(); ++j)
			{
				if (std::tolower(static_cast<unsigned char>(entry[i + j])) != kKey[j])
				{
					hit = false;
					break;
				}
			}
			if (!hit) continue;

			size_t v = i + kKey.size();
			size_t e = v;
			while (e < entry.size() && std::isdigit(static_cast<unsigned char>(entry[e]))) ++e;
			return parseUint(entry.substr(v, e - v), SipRegistrationClient::kMaxExpiresSec, out);
		}
		return false;
	}

	// Split a Contact header value on the commas that separate BINDINGS, honouring
	// <> and quoted display names (both of which may legally contain a comma), and
	// hand each binding to `fn`.
	template <typename Fn>
	void forEachContact(std::string_view v, Fn&& fn)
	{
		size_t start = 0;
		int angle = 0;
		bool quoted = false;
		for (size_t i = 0; i < v.size(); ++i)
		{
			const char c = v[i];
			if (quoted)
			{
				if (c == '"') quoted = false;
				continue;
			}
			if (c == '"')      quoted = true;
			else if (c == '<') ++angle;
			else if (c == '>') { if (angle > 0) --angle; }
			else if (c == ',' && angle == 0)
			{
				fn(v.substr(start, i - start));
				start = i + 1;
			}
		}
		if (start <= v.size())
		{
			fn(v.substr(start));
		}
	}
}

SipRegistrationClient::~SipRegistrationClient()
{
	wipe(_password, sizeof(_password));
}

bool SipRegistrationClient::configure(const Config& cfg, std::string_view password)
{
	// Refuse rather than truncate. Every one of these ends up inside a hash or a
	// Request-URI, so a silent shortening is an unauthenticatable trunk with no
	// symptom other than a permanent 401.
	if (cfg.registrarHost[0] == '\0' || cfg.domain[0] == '\0' ||
	    cfg.aorUser[0] == '\0' || cfg.authUser[0] == '\0' || cfg.localIp[0] == '\0')
	{
		return false;
	}
	if (password.empty() || password.size() + 1 > kMaxSecret)
	{
		return false;
	}
	// The Config arrays are already bounded by their own declarations; what is
	// NOT guaranteed is NUL-termination if a caller memcpy'd into them.
	if (cfg.registrarHost[kMaxHost - 1] != '\0' || cfg.domain[kMaxHost - 1] != '\0' ||
	    cfg.aorUser[kMaxUser - 1] != '\0' || cfg.authUser[kMaxUser - 1] != '\0' ||
	    cfg.localIp[kMaxIp - 1] != '\0')
	{
		return false;
	}

	wipe(_password, sizeof(_password));
	if (!copyBounded(_password, sizeof(_password), password))
	{
		return false;
	}

	_cfg = cfg;
	_requestedExpiresSec = cfg.requestedExpiresSec ? cfg.requestedExpiresSec
	                                               : kDefaultExpiresSec;
	if (_requestedExpiresSec > kMaxExpiresSec) _requestedExpiresSec = kMaxExpiresSec;

	// A fresh registration is a fresh Call-ID and a fresh From tag (RFC 3261
	// §10.2: reusing the previous Call-ID with a LOWER CSeq is exactly how a
	// reboot gets its REGISTER rejected as out of order, so the safe move on a
	// reconfigure is a new Call-ID rather than a resumed one).
	const std::string cid = IDGen::GenerateID(16);
	const std::string tag = IDGen::GenerateID(12);
	copyBounded(_callId, sizeof(_callId), cid);
	copyBounded(_fromTag, sizeof(_fromTag), tag);

	_cseq                = 0;
	_haveChallenge       = false;
	_nc                  = 0;
	_state               = State::Idle;
	_sendArmed           = false;
	_sendAtMs            = 0;
	_sentAtMs            = 0;
	_refreshAtMs         = 0;
	_bindingExpiresAtMs  = 0;
	_grantedExpiresSec   = 0;
	_authAttempts        = 0;
	_minExpiresApplied   = false;
	_consecutiveFailures = 0;
	_registerAttempts    = 0;
	_lastStatusCode      = 0;
	_authenticated       = false;
	_lastError[0]        = '\0';
	_configured          = true;
	return true;
}

void SipRegistrationClient::clearCredentials()
{
	wipe(_password, sizeof(_password));
	_haveChallenge = false;
	_nc            = 0;
	_authenticated = false;
	_configured    = false;
	_state         = State::Idle;
	_sendArmed     = false;
}

void SipRegistrationClient::start(uint64_t nowMs)
{
	if (!_configured) return;
	// Idempotent: only an Idle client with nothing armed needs kicking. A client
	// that is Registering, Registered or already backing off has a decision
	// pending and must not have it reset by a stray start().
	if (_state != State::Idle || _sendArmed) return;
	armSend(nowMs);
}

void SipRegistrationClient::stop()
{
	_state     = State::Idle;
	_sendArmed = false;
}

void SipRegistrationClient::armSend(uint64_t whenMs)
{
	_sendArmed = true;
	_sendAtMs  = whenMs;
}

uint64_t SipRegistrationClient::backoffMs() const
{
	if (_consecutiveFailures == 0) return kBackoffBaseMs;
	// Shift is clamped before it is applied: 1u << 32 is undefined behaviour on
	// every Cortex-M and x86 toolchain we build with, and a trunk that has failed
	// 40 times in a row is precisely when it would bite.
	uint32_t shift = _consecutiveFailures - 1;
	if (shift > 8) shift = 8;
	uint64_t d = kBackoffBaseMs << shift;
	return (d > kBackoffCapMs) ? kBackoffCapMs : d;
}

// A null `reason` PRESERVES whatever is already there. That is how a caller that
// has already recorded a precise error (composeRegister) routes through
// failCycle() without either clobbering it or handing setError() a pointer into
// its own destination buffer, which would be an overlapping copy.
void SipRegistrationClient::setError(const char* reason)
{
	if (!reason) return;
	_lastError[0] = '\0';
	copyBounded(_lastError, sizeof(_lastError), std::string_view(reason));
}

void SipRegistrationClient::failCycle(uint64_t nowMs, int code, const char* reason,
                                      uint64_t retryAfterMs)
{
	_state = State::Failed;
	if (_consecutiveFailures < 0xFFFFFFFFu) ++_consecutiveFailures;
	_lastStatusCode = static_cast<uint16_t>(code < 0 ? 0 : code);
	setError(reason);

	// A Retry-After never SHORTENS our own backoff — that would let a server talk
	// us into hammering it — it can only extend it.
	uint64_t delay = backoffMs();
	if (retryAfterMs > delay) delay = retryAfterMs;

	_authAttempts      = 0;
	_minExpiresApplied = false;
	armSend(nowMs + delay);
}

bool SipRegistrationClient::cacheChallenge(const SipDigest::DigestChallenge& ch)
{
	// Refuse an oversized field rather than truncate it (see copyBounded).
	char realm[kMaxHost], nonce[kMaxNonce], opaque[kMaxNonce];
	char algo[kMaxAlgo], qop[kMaxQop];
	if (!copyBounded(realm,  sizeof(realm),  ch.realm))     return false;
	if (!copyBounded(nonce,  sizeof(nonce),  ch.nonce))     return false;
	if (!copyBounded(opaque, sizeof(opaque), ch.opaque))    return false;
	if (!copyBounded(algo,   sizeof(algo),   ch.algorithm)) return false;
	if (!copyBounded(qop,    sizeof(qop),    ch.qopList))   return false;

	// A NEW nonce restarts the count. RFC 7616 §3.4.3: nc counts requests sent
	// with THIS nonce, so carrying the old count over is a replay-detector
	// tripwire on a strict SBC.
	if (!_haveChallenge || std::strcmp(_chNonce, nonce) != 0)
	{
		_nc = 0;
	}

	std::memcpy(_chRealm,     realm,  sizeof(realm));
	std::memcpy(_chNonce,     nonce,  sizeof(nonce));
	std::memcpy(_chOpaque,    opaque, sizeof(opaque));
	std::memcpy(_chAlgorithm, algo,   sizeof(algo));
	std::memcpy(_chQop,       qop,    sizeof(qop));
	_chStale       = ch.stale;
	_chProxy       = ch.proxy;
	_haveChallenge = true;
	return true;
}

SipDigest::DigestChallenge SipRegistrationClient::cachedChallenge() const
{
	SipDigest::DigestChallenge ch;
	ch.realm     = _chRealm;
	ch.nonce     = _chNonce;
	ch.opaque    = _chOpaque;
	ch.algorithm = _chAlgorithm;
	ch.qopList   = _chQop;
	ch.stale     = _chStale;
	ch.proxy     = _chProxy;
	return ch;
}

bool SipRegistrationClient::composeRegister(Request& out)
{
	// Request-URI of a REGISTER names the REGISTRAR's domain, not a user
	// (RFC 3261 §10.2). It is also the digest `uri` parameter, so the two must be
	// the same bytes — HA2 is MD5(method:uri) and an SBC that sees a different
	// uri in the header than in the Request-URI rejects the whole credential.
	char requestUri[kMaxHost + 16];
	int n;
	if (_cfg.registrarPort != 0 && _cfg.registrarPort != 5060)
	{
		n = std::snprintf(requestUri, sizeof(requestUri), "sip:%s:%u",
		                  _cfg.registrarHost, static_cast<unsigned>(_cfg.registrarPort));
	}
	else
	{
		n = std::snprintf(requestUri, sizeof(requestUri), "sip:%s", _cfg.registrarHost);
	}
	if (n < 0 || static_cast<size_t>(n) >= sizeof(requestUri))
	{
		setError("registrar host too long");
		return false;
	}

	// Authorization, if we are answering a cached challenge. nc increments HERE,
	// on the request that actually carries it — not on the challenge — because
	// the count is "requests sent with this nonce".
	std::string authValue;
	const char* authName = nullptr;
	if (_haveChallenge)
	{
		const SipDigest::DigestChallenge ch = cachedChallenge();
		const uint32_t nextNc = _nc + 1;
		const std::string cnonce = SipDigest::makeCnonce();
		if (!SipDigest::buildAuthorization(ch, _cfg.authUser, _password,
		                                   "REGISTER", requestUri,
		                                   nextNc, cnonce, authValue))
		{
			// Unanswerable challenge (SHA-256, auth-int only, MD5-sess with no
			// qop). Refusing to ANSWER is the point: an MD5 response to a SHA-256
			// challenge loops forever against a server that will never accept it.
			//
			// But the cached challenge must also be DROPPED, or the refusal is
			// permanent in a much worse way: every backed-off retry would rebuild
			// the same impossible Authorization, fail here, and never put a single
			// byte on the wire again. Dropping it means the next retry sends an
			// unauthenticated REGISTER and draws a FRESH challenge -- which is the
			// only way the client ever sees a different one. That matters
			// concretely: RFC 7616 3.7 lets a server offer one challenge per
			// algorithm (the 3.9.1 example sends SHA-256 AND MD5), so "the
			// challenge we happened to cache is unanswerable" is not the same
			// statement as "this server is unanswerable".
			_haveChallenge = false;
			_nc            = 0;
			setError("challenge cannot be answered (algorithm or qop)");
			return false;
		}
		authName = SipDigest::authorizationHeaderName(ch);
		_nc      = nextNc;
	}

	// Held in a named local: it is the backing store for the %s below, and a
	// temporary built inline inside the snprintf argument list is a dangling-
	// pointer bug waiting for someone to "simplify" the expression.
	const std::string authLine = authName ? (authValue + "\r\n") : std::string();

	const std::string branch = "z9hG4bK" + IDGen::GenerateID(12);
	const uint32_t cseq = _cseq + 1;

	n = std::snprintf(out.bytes, sizeof(out.bytes),
		"REGISTER %s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP %s:%u;branch=%s;rport\r\n"
		"Max-Forwards: 70\r\n"
		"From: <sip:%s@%s>;tag=%s\r\n"
		"To: <sip:%s@%s>\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u REGISTER\r\n"
		"Contact: <sip:%s@%s:%u>\r\n"
		"Expires: %u\r\n"
		"%s%s%s"
		"User-Agent: pocket-dial\r\n"
		"Content-Length: 0\r\n"
		"\r\n",
		requestUri,
		_cfg.localIp, static_cast<unsigned>(_cfg.localPort), branch.c_str(),
		_cfg.aorUser, _cfg.domain, _fromTag,
		_cfg.aorUser, _cfg.domain,
		_callId,
		static_cast<unsigned>(cseq),
		_cfg.aorUser, _cfg.localIp, static_cast<unsigned>(_cfg.localPort),
		static_cast<unsigned>(_requestedExpiresSec),
		authName ? authName : "", authName ? ": " : "", authLine.c_str());

	if (n < 0 || static_cast<size_t>(n) >= sizeof(out.bytes))
	{
		// NEVER send a truncated SIP message. snprintf would have handed us a
		// syntactically valid-looking prefix with half an Authorization header on
		// the end, which an SBC answers with 400 and a support ticket.
		out.len = 0;
		setError("REGISTER exceeds the fixed request buffer");
		return false;
	}

	out.len = static_cast<size_t>(n);
	_cseq   = cseq;
	return true;
}

bool SipRegistrationClient::tick(uint64_t nowMs, Request& out)
{
	if (!_configured) return false;
	// Idle with a send armed means start() was called on a configured client;
	// fall through so the first REGISTER can go out.
	if (_state == State::Idle && !_sendArmed) return false;

	// Timer F: a REGISTER with no final response inside 32 s is a failure, not a
	// permanent Registering.
	if (_state == State::Registering && nowMs >= _sentAtMs + kTransactionTimeoutMs)
	{
		failCycle(nowMs, 0, "no response from registrar (timer F)");
		return false;
	}

	// A live registration reaching its refresh point starts a new cycle.
	if (_state == State::Registered && !_sendArmed && nowMs >= _refreshAtMs)
	{
		armSend(nowMs);
	}

	if (!_sendArmed || nowMs < _sendAtMs)
	{
		return false;
	}

	if (!composeRegister(out))
	{
		// composeRegister already recorded the precise reason; nullptr preserves
		// it. This is a configuration-class fault, not a network one, so it backs
		// off like any other failure rather than retrying the identical
		// impossible request on the very next tick.
		failCycle(nowMs, 0, nullptr);
		return false;
	}

	_sendArmed = false;
	_sentAtMs  = nowMs;
	_state     = State::Registering;
	if (_registerAttempts < 0xFFFFFFFFu) ++_registerAttempts;
	return true;
}

void SipRegistrationClient::onResponse(uint64_t nowMs, const ResponseView& r)
{
	if (!_configured || _state != State::Registering)
	{
		// Stray: a late retransmission, or a response to a transaction we already
		// gave up on. Acting on it would resurrect a dead cycle.
		return;
	}

	// Provisional. A registrar rarely sends one, but a proxy in the path may.
	// It ends nothing (RFC 3261 §17.1.2) — keep waiting.
	if (r.code >= 100 && r.code < 200)
	{
		return;
	}

	_lastStatusCode = static_cast<uint16_t>(r.code);

	// ── 2xx ───────────────────────────────────────────────────────────────────
	if (r.code >= 200 && r.code < 300)
	{
		// Honour what the SERVER granted, never what we asked for. Registrars
		// routinely shorten the lease, and refreshing on the requested value
		// means the binding lapses before we ever retry.
		//
		// Precedence is RFC 3261 §10.2.4/§10.3 step 8: the granted lease rides on
		// the ;expires parameter of OUR binding in the Contact list. Only when
		// there is no such parameter does the Expires header apply.
		uint32_t granted = 0;
		bool haveGranted = false;

		if (!r.contact.empty())
		{
			// Match OUR contact first. An SBC that is holding a second binding for
			// the same AOR returns both, and taking the first one's lease would
			// arm our refresh timer off somebody else's registration.
			char mine[kMaxIp + 16];
			std::snprintf(mine, sizeof(mine), "%s:%u", _cfg.localIp,
			              static_cast<unsigned>(_cfg.localPort));
			const std::string_view mineSv(mine);

			uint32_t firstAny = 0;
			bool haveAny = false;
			forEachContact(r.contact, [&](std::string_view entry) {
				uint32_t v = 0;
				if (!expiresParamOf(entry, v)) return;
				if (!haveAny) { firstAny = v; haveAny = true; }
				if (!haveGranted && entry.find(mineSv) != std::string_view::npos)
				{
					granted = v;
					haveGranted = true;
				}
			});
			if (!haveGranted && haveAny)
			{
				// No binding named our transport address (a NAT rewrite, or an SBC
				// that rewrites Contact). One binding's lease is the best signal
				// available and is still the SERVER's number, not ours.
				granted = firstAny;
				haveGranted = true;
			}
		}

		if (!haveGranted && !r.expires.empty())
		{
			uint32_t v = 0;
			if (parseUint(r.expires, kMaxExpiresSec, v))
			{
				granted = v;
				haveGranted = true;
			}
		}

		if (!haveGranted)
		{
			// Neither form present. RFC 3261 §10.3 says the registrar MUST add the
			// expires parameter, but real stacks omit it; the binding then holds
			// for what we asked. Treated as granted-equals-requested, and named in
			// lastError so an operator can see WHY the refresh timer is what it is
			// without it being a failure.
			granted = _requestedExpiresSec;
			setError("registrar returned no Expires; assuming the requested lease");
		}
		else
		{
			_lastError[0] = '\0';
		}

		if (granted == 0)
		{
			// A 0-second grant is the registrar saying "you are not registered".
			// Treating it as success would park us in Registered with a binding
			// that does not exist.
			failCycle(nowMs, r.code, "registrar granted a 0 second lease");
			return;
		}

		_grantedExpiresSec   = granted;
		_bindingExpiresAtMs  = nowMs + static_cast<uint64_t>(granted) * 1000ULL;

		// Refresh at 90% of the lease. The remaining 10% is deliberate retry
		// headroom: on a 3600 s carrier lease that is six minutes, enough for
		// several backed-off attempts before the binding actually lapses and
		// inbound calls start failing. Short leases fall back to half, because
		// 10% of 20 s is not enough time to retry anything.
		uint32_t refreshSec = (granted > 20) ? (granted - granted / 10) : (granted / 2);
		if (refreshSec == 0) refreshSec = 1;
		_refreshAtMs = nowMs + static_cast<uint64_t>(refreshSec) * 1000ULL;

		_state               = State::Registered;
		// "authenticated" means THIS registration was carried by a credential, not
		// merely that a challenge was seen at some point. An IP-authenticated
		// trunk never sets it, which is exactly the distinction an operator
		// staring at a dashboard needs.
		_authenticated       = _haveChallenge;
		_consecutiveFailures = 0;
		_authAttempts        = 0;
		_minExpiresApplied   = false;
		_sendArmed           = false;
		// The cached challenge is KEPT: the next refresh authenticates
		// pre-emptively with nc+1 against the same nonce and skips a 401.
		return;
	}

	// ── 401 / 407 ─────────────────────────────────────────────────────────────
	if (r.code == 401 || r.code == 407)
	{
		const bool proxy = (r.code == 407);
		std::string_view hdr = proxy ? r.proxyAuthenticate : r.wwwAuthenticate;
		if (hdr.empty())
		{
			// Some SBCs send the wrong one for the code. Accept the other rather
			// than fail, but keep the code's own semantics for which header we
			// answer under — parseChallenge takes that from the header NAME when
			// one is present.
			hdr = proxy ? r.wwwAuthenticate : r.proxyAuthenticate;
		}
		if (hdr.empty())
		{
			failCycle(nowMs, r.code, "challenge with no Authenticate header");
			return;
		}

		SipDigest::DigestChallenge ch;
		if (!SipDigest::parseChallenge(std::string(hdr), ch, proxy))
		{
			failCycle(nowMs, r.code, "unparseable challenge");
			return;
		}

		// Wrong-password detection. If we already answered THIS nonce and the
		// server challenged again with the SAME nonce and did NOT mark it stale,
		// the credential is what it rejected — not the nonce. Retrying cannot
		// help, and retrying fast is how an account gets auto-blacklisted.
		if (_haveChallenge && _nc > 0 && !ch.stale &&
		    ch.nonce == std::string_view(_chNonce))
		{
			_haveChallenge = false;
			_nc            = 0;
			_authenticated = false;
			failCycle(nowMs, r.code, "credentials rejected (re-challenged, not stale)");
			return;
		}

		if (_authAttempts + 1 > kMaxAuthAttempts)
		{
			failCycle(nowMs, r.code, "too many challenges in one cycle");
			return;
		}

		if (!cacheChallenge(ch))
		{
			failCycle(nowMs, r.code, "challenge field exceeds a fixed buffer");
			return;
		}

		++_authAttempts;
		// Retry immediately: a stale nonce or a first challenge is a normal part
		// of the exchange, not a failure, so it must not consume backoff.
		armSend(nowMs);
		return;
	}

	// ── 423 Interval Too Brief ────────────────────────────────────────────────
	if (r.code == 423)
	{
		if (_minExpiresApplied)
		{
			// We already adopted a Min-Expires this cycle and were told again.
			// Retrying would loop against a server that keeps moving the floor.
			failCycle(nowMs, r.code, "423 again after adopting Min-Expires");
			return;
		}
		uint32_t minExp = 0;
		if (r.minExpires.empty() || !parseUint(r.minExpires, kMaxExpiresSec, minExp) ||
		    minExp == 0)
		{
			// RFC 3261 §10.3 step 7 makes Min-Expires mandatory on a 423. Without
			// a usable one there is no new value to try.
			failCycle(nowMs, r.code, "423 with no usable Min-Expires");
			return;
		}
		if (minExp > _requestedExpiresSec)
		{
			_requestedExpiresSec = minExp;
		}
		_minExpiresApplied = true;
		setError("registrar required a longer lease (423)");
		armSend(nowMs);  // immediate retry, NOT a backoff — this is a negotiation
		return;
	}

	// ── 3xx ───────────────────────────────────────────────────────────────────
	if (r.code >= 300 && r.code < 400)
	{
		// A registrar redirect (RFC 3261 §10.3 step 3 / §8.1.3.4) would have us
		// re-target the Contact list. Not implemented — and saying so is better
		// than silently retrying the same registrar until the backoff cap.
		failCycle(nowMs, r.code, "redirect response not followed");
		return;
	}

	// ── everything else ───────────────────────────────────────────────────────
	uint64_t retryAfterMs = 0;
	if (!r.retryAfter.empty())
	{
		// Retry-After may carry a comment/parameters ("120 (until 3pm)"); only the
		// leading delta-seconds is read.
		size_t e = 0;
		while (e < r.retryAfter.size() &&
		       std::isdigit(static_cast<unsigned char>(r.retryAfter[e]))) ++e;
		uint32_t secs = 0;
		if (e > 0 && parseUint(r.retryAfter.substr(0, e), kMaxExpiresSec, secs))
		{
			retryAfterMs = static_cast<uint64_t>(secs) * 1000ULL;
		}
	}
	failCycle(nowMs, r.code, "registrar rejected the REGISTER", retryAfterMs);
}

SipRegistrationClient::Status SipRegistrationClient::status() const
{
	Status s;
	s.state               = _state;
	s.grantedExpiresSec   = _grantedExpiresSec;
	s.requestedExpiresSec = _requestedExpiresSec;
	s.nextActionMs        = _sendArmed ? _sendAtMs
	                                   : (_state == State::Registered ? _refreshAtMs : 0);
	s.bindingExpiresAtMs  = _bindingExpiresAtMs;
	s.consecutiveFailures = _consecutiveFailures;
	s.registerAttempts    = _registerAttempts;
	s.lastStatusCode      = _lastStatusCode;
	s.authenticated       = _authenticated;
	std::memcpy(s.lastError, _lastError, sizeof(s.lastError));
	return s;
}
