#ifndef JSON_READER_HPP
#define JSON_READER_HPP

// JsonReader: a small, strict, dependency-free JSON reader.
//
// Why this exists: JsonEscape.hpp only ESCAPES (writing JSON out); cJSON is
// ESP-only (gated out of the host build, and out of every non-ESP transport —
// see TelephonyAnchorLogic.hpp's file comment for the same constraint on the
// JWT decode path). Issue #186's config IMPORT is the first feature in this
// codebase that needs to READ a JSON document, on host and on-device alike,
// so this inverts exactly what jsonEscape() emits, with the same
// dependency-free/host-and-ESP-identical rationale AdminAuth.cpp's hand-rolled
// SHA-256 already established for this project.
//
// Deliberately NOT a general-purpose/spec-complete parser: no \uXXXX surrogate
// pairs beyond a single BMP escape, no big-number precision guarantees (numbers
// land in a double), no comments, no trailing commas. It is sized for reading
// back a config-export blob this SAME codebase produced, not for parsing
// arbitrary third-party JSON. Bounded on both depth (kMaxDepth) and input size
// (kMaxBytes) so a malformed or hostile body can only ever fail fast, never
// recurse or allocate without bound — see parse()'s contract.

#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <cstdlib>

namespace JsonReader
{
	// Depth cap: a config-export blob nests at most
	// object -> {plaintext|secretsEnc} -> array -> object -> (no further
	// nesting) — 4 deep in practice. 8 leaves comfortable headroom without
	// admitting a pathological "((((((((...".
	constexpr int kMaxDepth = 8;
	// Matches HttpServer's existing MAX_BODY_BYTES (16 KB) for the buffered
	// POST path every import request arrives through — see handleClient().
	// Enforced here too so this reader is safe to reuse against an
	// independently-sized buffer without re-deriving the limit.
	constexpr size_t kMaxBytes = 16384;

	struct Value
	{
		enum class Type : uint8_t { Null, Bool, Number, String, Array, Object };

		Type type = Type::Null;
		bool boolVal = false;
		double numVal = 0.0;
		std::string strVal;
		std::vector<Value> arrVal;
		// Byte offsets of this value within the text passed to parse() — the
		// EXACT source bytes, whitespace and all, not a re-serialization.
		// Issue #186's config-import handler uses this on the "plaintext"
		// member specifically: it needs the identical bytes that were sealed
		// as the encrypted block's AAD at export time, and re-serializing a
		// parsed Value can never be guaranteed byte-identical to what a
		// different piece of code (the export handler's ostringstream build)
		// originally wrote. 0/0 (both default) for a value nobody needs the
		// span of.
		size_t spanStart = 0;
		size_t spanEnd = 0;
		// Objects keep insertion order and allow duplicate keys on the wire
		// (last one wins on lookup) rather than silently rejecting them —
		// simpler than detecting duplicates for a reader that only ever reads
		// this codebase's own output.
		std::vector<std::pair<std::string, Value>> objVal;

		bool isObject() const { return type == Type::Object; }
		bool isArray()  const { return type == Type::Array; }
		bool isString() const { return type == Type::String; }
		bool isNull()   const { return type == Type::Null; }

		// Object member lookup. Returns nullptr if this is not an object or the
		// key is absent — callers pair this with the `*OrDefault` helpers below
		// rather than dereferencing directly, so a missing/wrong-shaped field in
		// an otherwise-valid import blob degrades to "use the default" instead
		// of a crash.
		const Value* find(const std::string& key) const
		{
			if (type != Type::Object) return nullptr;
			for (auto it = objVal.rbegin(); it != objVal.rend(); ++it)
			{
				if (it->first == key) return &it->second;
			}
			return nullptr;
		}

		std::string stringOr(const std::string& key, const std::string& def = "") const
		{
			const Value* v = find(key);
			return (v && v->type == Type::String) ? v->strVal : def;
		}
		bool boolOr(const std::string& key, bool def = false) const
		{
			const Value* v = find(key);
			return (v && v->type == Type::Bool) ? v->boolVal : def;
		}
		double numberOr(const std::string& key, double def = 0.0) const
		{
			const Value* v = find(key);
			return (v && v->type == Type::Number) ? v->numVal : def;
		}
		int intOr(const std::string& key, int def = 0) const
		{
			const Value* v = find(key);
			return (v && v->type == Type::Number) ? static_cast<int>(v->numVal) : def;
		}
		// The array at `key`, or an empty vector if absent/wrong-shaped — never
		// null, so callers can range-for it unconditionally.
		const std::vector<Value>& arrayOr(const std::string& key) const
		{
			static const std::vector<Value> kEmpty;
			const Value* v = find(key);
			return (v && v->type == Type::Array) ? v->arrVal : kEmpty;
		}
	};

	namespace detail
	{
		struct Parser
		{
			const char* base;   // start of the ORIGINAL text, for span offsets
			const char* p;
			const char* end;
			int depth = 0;
			bool error = false;

			void skipWs()
			{
				while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
			}

			bool consume(char c)
			{
				if (p >= end || *p != c) { error = true; return false; }
				++p;
				return true;
			}

			bool parseHex4(unsigned& out)
			{
				if (end - p < 4) { error = true; return false; }
				out = 0;
				for (int i = 0; i < 4; ++i)
				{
					char c = p[i];
					out <<= 4;
					if (c >= '0' && c <= '9') out |= static_cast<unsigned>(c - '0');
					else if (c >= 'a' && c <= 'f') out |= static_cast<unsigned>(c - 'a' + 10);
					else if (c >= 'A' && c <= 'F') out |= static_cast<unsigned>(c - 'A' + 10);
					else { error = true; return false; }
				}
				p += 4;
				return true;
			}

			// Encodes a Unicode code point as UTF-8 into `out`. Only handles the
			// single-BMP-escape case (no surrogate-pair reassembly) — sufficient
			// for round-tripping this codebase's own jsonEscape() output, which
			// only ever emits \u00XX control-character escapes (ASCII range).
			void appendUtf8(std::string& out, unsigned cp)
			{
				if (cp <= 0x7F)
				{
					out.push_back(static_cast<char>(cp));
				}
				else if (cp <= 0x7FF)
				{
					out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
					out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
				}
				else
				{
					out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
					out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
					out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
				}
			}

			bool parseString(std::string& out)
			{
				if (!consume('"')) return false;
				out.clear();
				while (true)
				{
					if (p >= end) { error = true; return false; }
					unsigned char c = static_cast<unsigned char>(*p);
					if (c == '"') { ++p; return true; }
					if (c == '\\')
					{
						++p;
						if (p >= end) { error = true; return false; }
						char esc = *p++;
						switch (esc)
						{
							case '"':  out.push_back('"');  break;
							case '\\': out.push_back('\\'); break;
							case '/':  out.push_back('/');  break;
							case 'b':  out.push_back('\b'); break;
							case 'f':  out.push_back('\f'); break;
							case 'n':  out.push_back('\n'); break;
							case 'r':  out.push_back('\r'); break;
							case 't':  out.push_back('\t'); break;
							case 'u':
							{
								unsigned cp;
								if (!parseHex4(cp)) return false;
								appendUtf8(out, cp);
								break;
							}
							default:
								error = true;
								return false;
						}
					}
					else if (c < 0x20)
					{
						// Raw control characters are not valid inside a JSON
						// string (RFC 8259 §7) — reject rather than silently pass
						// through, which is exactly the kind of thing that lets a
						// smuggled separator corrupt a downstream NVS/PBX field.
						error = true;
						return false;
					}
					else
					{
						out.push_back(static_cast<char>(c));
						++p;
					}
				}
			}

			bool parseNumber(double& out)
			{
				const char* start = p;
				if (p < end && *p == '-') ++p;
				if (p >= end || *p < '0' || *p > '9') { error = true; return false; }
				while (p < end && *p >= '0' && *p <= '9') ++p;
				if (p < end && *p == '.')
				{
					++p;
					if (p >= end || *p < '0' || *p > '9') { error = true; return false; }
					while (p < end && *p >= '0' && *p <= '9') ++p;
				}
				if (p < end && (*p == 'e' || *p == 'E'))
				{
					++p;
					if (p < end && (*p == '+' || *p == '-')) ++p;
					if (p >= end || *p < '0' || *p > '9') { error = true; return false; }
					while (p < end && *p >= '0' && *p <= '9') ++p;
				}
				out = std::strtod(std::string(start, p).c_str(), nullptr);
				return true;
			}

			bool parseLiteral(const char* lit, size_t len)
			{
				if (end - p < static_cast<long>(len) || std::string(p, p + len) != lit)
				{
					error = true;
					return false;
				}
				p += len;
				return true;
			}

			bool parseValue(Value& out)
			{
				if (++depth > kMaxDepth) { error = true; --depth; return false; }
				skipWs();
				const char* valueStart = p;
				bool ok = parseValueInner(out);
				if (ok)
				{
					out.spanStart = static_cast<size_t>(valueStart - base);
					out.spanEnd = static_cast<size_t>(p - base);
				}
				--depth;
				return ok;
			}

			bool parseValueInner(Value& out)
			{
				if (p >= end) { error = true; return false; }
				char c = *p;
				if (c == '{') return parseObject(out);
				if (c == '[') return parseArray(out);
				if (c == '"')
				{
					out.type = Value::Type::String;
					return parseString(out.strVal);
				}
				if (c == 't')
				{
					if (!parseLiteral("true", 4)) return false;
					out.type = Value::Type::Bool;
					out.boolVal = true;
					return true;
				}
				if (c == 'f')
				{
					if (!parseLiteral("false", 5)) return false;
					out.type = Value::Type::Bool;
					out.boolVal = false;
					return true;
				}
				if (c == 'n')
				{
					if (!parseLiteral("null", 4)) return false;
					out.type = Value::Type::Null;
					return true;
				}
				if (c == '-' || (c >= '0' && c <= '9'))
				{
					out.type = Value::Type::Number;
					return parseNumber(out.numVal);
				}
				error = true;
				return false;
			}

			bool parseObject(Value& out)
			{
				out.type = Value::Type::Object;
				if (!consume('{')) return false;
				skipWs();
				if (p < end && *p == '}') { ++p; return true; }
				while (true)
				{
					skipWs();
					std::string key;
					if (!parseString(key)) return false;
					skipWs();
					if (!consume(':')) return false;
					skipWs();
					Value v;
					if (!parseValue(v)) return false;
					out.objVal.emplace_back(std::move(key), std::move(v));
					skipWs();
					if (p >= end) { error = true; return false; }
					if (*p == ',') { ++p; continue; }
					if (*p == '}') { ++p; return true; }
					error = true;
					return false;
				}
			}

			bool parseArray(Value& out)
			{
				out.type = Value::Type::Array;
				if (!consume('[')) return false;
				skipWs();
				if (p < end && *p == ']') { ++p; return true; }
				while (true)
				{
					skipWs();
					Value v;
					if (!parseValue(v)) return false;
					out.arrVal.push_back(std::move(v));
					skipWs();
					if (p >= end) { error = true; return false; }
					if (*p == ',') { ++p; continue; }
					if (*p == ']') { ++p; return true; }
					error = true;
					return false;
				}
			}
		};
	}

	// Parses `text` into `out`. Returns false (with `err` set to a short,
	// non-sensitive reason — never echoes attacker-controlled bytes back) on
	// any malformed input, oversized input, or excess nesting; `out` is left
	// in an unspecified state on failure and must not be used.
	inline bool parse(const std::string& text, Value& out, std::string& err)
	{
		if (text.size() > kMaxBytes)
		{
			err = "input exceeds size limit";
			return false;
		}
		detail::Parser parser;
		parser.base = text.data();
		parser.p = text.data();
		parser.end = text.data() + text.size();
		parser.skipWs();
		if (!parser.parseValue(out))
		{
			err = "malformed JSON";
			return false;
		}
		parser.skipWs();
		if (parser.p != parser.end)
		{
			err = "trailing data after JSON value";
			return false;
		}
		return true;
	}
}

#endif // JSON_READER_HPP
