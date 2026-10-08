#include <gtest/gtest.h>
#include "AudioSocketFrame.hpp"
#include "ApidazeAnchorClient.hpp"

#include <vector>
#include <string>
#include <cstring>

TEST(AudioSocketTest, HeaderEncodeDecodeByteExact)
{
	uint8_t hdr[pd::audiosocket::kHeaderBytes]{};
	pd::audiosocket::encodeHeader(pd::audiosocket::Type::Audio, 320, hdr);

	// Byte 0: Type 0x10
	EXPECT_EQ(hdr[0], 0x10);
	// Bytes 1-2: Big-endian 320 (0x0140)
	EXPECT_EQ(hdr[1], 0x01);
	EXPECT_EQ(hdr[2], 0x40);

	pd::audiosocket::Type decodedType;
	uint16_t decodedLen = 0;
	EXPECT_TRUE(pd::audiosocket::decodeHeader(hdr, decodedType, decodedLen));
	EXPECT_EQ(decodedType, pd::audiosocket::Type::Audio);
	EXPECT_EQ(decodedLen, 320);
}

TEST(AudioSocketTest, AudioFrameEncode20msExact)
{
	int16_t samples[pd::audiosocket::kSamplesPer20ms]{};
	for (size_t i = 0; i < pd::audiosocket::kSamplesPer20ms; ++i)
	{
		samples[i] = static_cast<int16_t>(i * 100);
	}

	uint8_t outBuf[pd::audiosocket::kTotalAudioFrameBytes]{};
	size_t written = pd::audiosocket::encodeAudioFrame(samples, pd::audiosocket::kSamplesPer20ms, outBuf, sizeof(outBuf));

	EXPECT_EQ(written, pd::audiosocket::kTotalAudioFrameBytes);
	EXPECT_EQ(written, 323);
	EXPECT_EQ(outBuf[0], 0x10);
	EXPECT_EQ(outBuf[1], 0x01);
	EXPECT_EQ(outBuf[2], 0x40);

	// Verify sample payload match
	const int16_t* payloadSamples = reinterpret_cast<const int16_t*>(&outBuf[pd::audiosocket::kHeaderBytes]);
	for (size_t i = 0; i < pd::audiosocket::kSamplesPer20ms; ++i)
	{
		EXPECT_EQ(payloadSamples[i], samples[i]);
	}

	// Buffer too small fails cleanly
	uint8_t smallBuf[100]{};
	EXPECT_EQ(pd::audiosocket::encodeAudioFrame(samples, pd::audiosocket::kSamplesPer20ms, smallBuf, sizeof(smallBuf)), 0);
}

TEST(AudioSocketTest, IdFrameEncodeStringAndBinary)
{
	const std::string uuidStr = "123e4567-e89b-12d3-a456-426614174000";
	uint8_t outBuf[64]{};
	size_t written = pd::audiosocket::encodeIdFrame(uuidStr, outBuf, sizeof(outBuf));

	EXPECT_EQ(written, pd::audiosocket::kHeaderBytes + uuidStr.size());
	EXPECT_EQ(outBuf[0], 0x01); // Type::Id
	EXPECT_EQ(outBuf[1], 0x00);
	EXPECT_EQ(outBuf[2], 36);   // 36-char string

	std::string decoded(reinterpret_cast<const char*>(&outBuf[pd::audiosocket::kHeaderBytes]), 36);
	EXPECT_EQ(decoded, uuidStr);
}

TEST(AudioSocketTest, HangupAndErrorFrameEncode)
{
	uint8_t hangupBuf[8]{};
	size_t hangupLen = pd::audiosocket::encodeHangupFrame(hangupBuf, sizeof(hangupBuf));
	EXPECT_EQ(hangupLen, 3);
	EXPECT_EQ(hangupBuf[0], 0x00);
	EXPECT_EQ(hangupBuf[1], 0x00);
	EXPECT_EQ(hangupBuf[2], 0x00);

	uint8_t errBuf[64]{};
	const std::string errMsg = "Call Rejected";
	size_t errLen = pd::audiosocket::encodeErrorFrame(42, errMsg, errBuf, sizeof(errBuf));
	EXPECT_EQ(errLen, 3 + 1 + errMsg.size());
	EXPECT_EQ(errBuf[0], 0xFF);
	EXPECT_EQ(errBuf[3], 42);
	std::string decodedErr(reinterpret_cast<const char*>(&errBuf[4]), errMsg.size());
	EXPECT_EQ(decodedErr, errMsg);
}

TEST(AudioSocketTest, StreamParserIncrementalAndMultiFrame)
{
	pd::audiosocket::StreamParser parser;

	// Build two consecutive frames: an Id frame then an Audio frame
	uint8_t idFrame[64]{};
	const std::string uuid = "my-call-id-99";
	size_t idLen = pd::audiosocket::encodeIdFrame(uuid, idFrame, sizeof(idFrame));

	int16_t samples[pd::audiosocket::kSamplesPer20ms]{};
	uint8_t audioFrame[pd::audiosocket::kTotalAudioFrameBytes]{};
	size_t audioLen = pd::audiosocket::encodeAudioFrame(samples, pd::audiosocket::kSamplesPer20ms, audioFrame, sizeof(audioFrame));

	std::vector<uint8_t> stream;
	stream.insert(stream.end(), idFrame, idFrame + idLen);
	stream.insert(stream.end(), audioFrame, audioFrame + audioLen);

	// Push byte-by-byte to test fragmented receipt
	size_t framesFound = 0;
	pd::audiosocket::FrameView view;

	for (size_t i = 0; i < stream.size(); ++i)
	{
		parser.pushBytes(&stream[i], 1);
		while (parser.popFrame(view))
		{
			if (framesFound == 0)
			{
				EXPECT_TRUE(view.isId());
				EXPECT_EQ(view.payloadLength, uuid.size());
				std::string parsedUuid(reinterpret_cast<const char*>(view.payload), view.payloadLength);
				EXPECT_EQ(parsedUuid, uuid);
			}
			else if (framesFound == 1)
			{
				EXPECT_TRUE(view.isAudio());
				EXPECT_EQ(view.payloadLength, pd::audiosocket::kAudioPayloadBytes);
			}
			framesFound++;
		}
	}

	EXPECT_EQ(framesFound, 2);
	EXPECT_EQ(parser.bufferedBytes(), 0);
}

TEST(AudioSocketTest, ApidazeAnchorClientScaffoldContract)
{
	pd::anchor::ApidazeAnchorClient client;

	EXPECT_FALSE(client.isConnected());
	EXPECT_FALSE(client.start()); // Not initialized

	EXPECT_TRUE(client.init("https://cpaas.apidaze.io", "key123", "sec456", "+15551234567"));
	EXPECT_TRUE(client.start());
	EXPECT_FALSE(client.isConnected()); // Transport not yet connected

	client.setSimulatedConnected(true);
	EXPECT_TRUE(client.isConnected());

	std::string ownLeg;
	EXPECT_TRUE(client.makeCall("+15559876543", &ownLeg));
	EXPECT_FALSE(ownLeg.empty());

	int16_t pcm[160]{};
	EXPECT_TRUE(client.writeAudio(ownLeg, pcm, 160));

	EXPECT_TRUE(client.answerCall(ownLeg));
	EXPECT_TRUE(client.dropCall(ownLeg));

	client.stop();
	EXPECT_FALSE(client.isConnected());
}
