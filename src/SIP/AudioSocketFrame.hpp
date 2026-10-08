#ifndef AUDIO_SOCKET_FRAME_HPP
#define AUDIO_SOCKET_FRAME_HPP

// AudioSocketFrame: Binary framing protocol for real-time audio streaming.
//
// Protocol Specification (Sean DuBois / AudioSocket RFC):
//   - 3-byte header:
//       uint8_t  type;
//       uint16_t length;  (big-endian / network byte order)
//   - Followed by `length` bytes of payload.
//
// Message Types:
//   - 0x00: Hangup (remote/local disconnect)
//   - 0x01: UUID / Identifier handshake
//   - 0x10: Audio payload (signed linear 16-bit 8kHz mono PCM, 320 bytes / 20ms)
//   - 0xFF: Error (error code + message)
//
// Invariants:
//   - Zero dynamic heap allocation in media pathways (writeAudio, encode/decode).
//   - Fully portable across host and ESP32-S3 architectures.
//
// Ref: docs/ADR-002-PROGRAMMABLE-MEDIA-ANCHOR.md (Part of #920, Epic #381).

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string_view>

namespace pd::audiosocket
{

enum class Type : uint8_t
{
	Hangup = 0x00,
	Id     = 0x01,
	Audio  = 0x10,
	Error  = 0xFF
};

// Protocol framing and media constants
constexpr size_t kHeaderBytes = 3;
constexpr uint32_t kSampleRate = 8000;
constexpr uint16_t kChannels = 1;
constexpr uint16_t kBitsPerSample = 16;
constexpr uint16_t kFrameDurationMs = 20;
constexpr size_t kSamplesPer20ms = (kSampleRate * kFrameDurationMs) / 1000; // 160 samples
constexpr size_t kAudioPayloadBytes = kSamplesPer20ms * sizeof(int16_t);      // 320 bytes
constexpr size_t kTotalAudioFrameBytes = kHeaderBytes + kAudioPayloadBytes;   // 323 bytes

// Maximum payload buffer size for stream parsing without allocation (1024 bytes)
constexpr size_t kMaxPayloadBytes = 1024;

inline uint16_t readBe16(const uint8_t* p)
{
	return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

inline void writeBe16(uint8_t* p, uint16_t v)
{
	p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
	p[1] = static_cast<uint8_t>(v & 0xFF);
}

// Non-owning view of a parsed AudioSocket frame
struct FrameView
{
	Type type{Type::Hangup};
	uint16_t payloadLength{0};
	const uint8_t* payload{nullptr};

	bool isAudio() const { return type == Type::Audio; }
	bool isId() const { return type == Type::Id; }
	bool isHangup() const { return type == Type::Hangup; }
	bool isError() const { return type == Type::Error; }
};

// Encode a 3-byte header
inline void encodeHeader(Type type, uint16_t payloadLen, uint8_t outHeader[kHeaderBytes])
{
	outHeader[0] = static_cast<uint8_t>(type);
	writeBe16(&outHeader[1], payloadLen);
}

// Decode a 3-byte header
inline bool decodeHeader(const uint8_t inHeader[kHeaderBytes], Type& outType, uint16_t& outPayloadLen)
{
	outType = static_cast<Type>(inHeader[0]);
	outPayloadLen = readBe16(&inHeader[1]);
	return true;
}

// Encode a PCM16 8kHz audio frame into a caller-provided buffer (zero heap allocation)
inline size_t encodeAudioFrame(const int16_t* pcmSamples, size_t sampleCount, uint8_t* outBuf, size_t outCapacity)
{
	const size_t payloadBytes = sampleCount * sizeof(int16_t);
	const size_t totalBytes = kHeaderBytes + payloadBytes;
	if (!pcmSamples || !outBuf || outCapacity < totalBytes || payloadBytes > 0xFFFF)
	{
		return 0;
	}
	encodeHeader(Type::Audio, static_cast<uint16_t>(payloadBytes), outBuf);
	std::memcpy(&outBuf[kHeaderBytes], pcmSamples, payloadBytes);
	return totalBytes;
}

// Encode an ID / UUID handshake frame
inline size_t encodeIdFrame(const uint8_t* uuidBytes, size_t uuidLen, uint8_t* outBuf, size_t outCapacity)
{
	const size_t totalBytes = kHeaderBytes + uuidLen;
	if (!uuidBytes || !outBuf || outCapacity < totalBytes || uuidLen > 0xFFFF)
	{
		return 0;
	}
	encodeHeader(Type::Id, static_cast<uint16_t>(uuidLen), outBuf);
	std::memcpy(&outBuf[kHeaderBytes], uuidBytes, uuidLen);
	return totalBytes;
}

inline size_t encodeIdFrame(std::string_view uuidStr, uint8_t* outBuf, size_t outCapacity)
{
	return encodeIdFrame(reinterpret_cast<const uint8_t*>(uuidStr.data()), uuidStr.size(), outBuf, outCapacity);
}

// Encode a Hangup frame
inline size_t encodeHangupFrame(uint8_t* outBuf, size_t outCapacity, const uint8_t* causeCode = nullptr)
{
	const uint16_t len = causeCode ? 1 : 0;
	const size_t totalBytes = kHeaderBytes + len;
	if (!outBuf || outCapacity < totalBytes)
	{
		return 0;
	}
	encodeHeader(Type::Hangup, len, outBuf);
	if (causeCode)
	{
		outBuf[kHeaderBytes] = *causeCode;
	}
	return totalBytes;
}

// Encode an Error frame
inline size_t encodeErrorFrame(uint8_t errorCode, std::string_view message, uint8_t* outBuf, size_t outCapacity)
{
	const size_t payloadBytes = 1 + message.size();
	const size_t totalBytes = kHeaderBytes + payloadBytes;
	if (!outBuf || outCapacity < totalBytes || payloadBytes > 0xFFFF)
	{
		return 0;
	}
	encodeHeader(Type::Error, static_cast<uint16_t>(payloadBytes), outBuf);
	outBuf[kHeaderBytes] = errorCode;
	if (!message.empty())
	{
		std::memcpy(&outBuf[kHeaderBytes + 1], message.data(), message.size());
	}
	return totalBytes;
}

// Fixed-capacity stream parser: assembles incoming stream bytes without allocation
template <size_t MaxPayload = kMaxPayloadBytes>
class StreamParser
{
public:
	StreamParser() = default;

	void reset()
	{
		_bytesBuffered = 0;
	}

	// Ingest bytes. Returns true if at least one complete frame is ready.
	bool pushBytes(const uint8_t* data, size_t len)
	{
		if (!data || len == 0)
		{
			return false;
		}
		for (size_t i = 0; i < len; ++i)
		{
			if (_bytesBuffered < sizeof(_buffer))
			{
				_buffer[_bytesBuffered++] = data[i];
			}
			else
			{
				// Overflow protection: reset to resynchronize
				reset();
				return false;
			}
		}
		return hasFrame();
	}

	bool hasFrame() const
	{
		if (_bytesBuffered < kHeaderBytes)
		{
			return false;
		}
		uint16_t payloadLen = readBe16(&_buffer[1]);
		return _bytesBuffered >= (kHeaderBytes + payloadLen);
	}

	bool popFrame(FrameView& outView)
	{
		if (!hasFrame())
		{
			return false;
		}
		outView.type = static_cast<Type>(_buffer[0]);
		outView.payloadLength = readBe16(&_buffer[1]);
		outView.payload = &_buffer[kHeaderBytes];

		const size_t totalFrameSize = kHeaderBytes + outView.payloadLength;
		const size_t remaining = _bytesBuffered - totalFrameSize;
		if (remaining > 0)
		{
			std::memmove(_buffer, &_buffer[totalFrameSize], remaining);
		}
		_bytesBuffered = remaining;
		return true;
	}

	size_t bufferedBytes() const { return _bytesBuffered; }

private:
	uint8_t _buffer[kHeaderBytes + MaxPayload]{};
	size_t _bytesBuffered{0};
};

} // namespace pd::audiosocket

#endif // AUDIO_SOCKET_FRAME_HPP
