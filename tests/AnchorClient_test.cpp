// AnchorClient_test.cpp — unit coverage for LoopbackAnchorClient, the reference
// AnchorClient implementation. Tests cover init/start/stop lifecycle, makeCall
// event delivery, audio loopback (writeAudio → AudioRxCallback), and inbound
// call simulation. No sockets or ESP hardware required.

#include <gtest/gtest.h>
#include "LoopbackAnchorClient.hpp"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

// ── Lifecycle ─────────────────────────────────────────────────────────────────

TEST(LoopbackAnchorClient, InitSucceeds) {
    LoopbackAnchorClient client;
    EXPECT_TRUE(client.init("http://localhost", "test-id", "secret", "100"));
}

TEST(LoopbackAnchorClient, NotConnectedBeforeStart) {
    LoopbackAnchorClient client;
    client.init("http://localhost", "test-id", "secret", "100");
    EXPECT_FALSE(client.isConnected());
}

TEST(LoopbackAnchorClient, StartSetsConnected) {
    LoopbackAnchorClient client;
    client.init("http://localhost", "test-id", "secret", "100");
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.isConnected());
}

TEST(LoopbackAnchorClient, StopDisconnects) {
    LoopbackAnchorClient client;
    client.init("http://localhost", "test-id", "secret", "100");
    client.start();
    client.stop();
    EXPECT_FALSE(client.isConnected());
}

TEST(LoopbackAnchorClient, MakeCallFailsIfNotStarted) {
    LoopbackAnchorClient client;
    client.init("http://localhost", "test-id", "secret", "100");
    EXPECT_FALSE(client.makeCall("200"));
}

// ── makeCall event delivery ───────────────────────────────────────────────────

TEST(LoopbackAnchorClient, MakeCallDeliversRingingThenAnswered) {
    LoopbackAnchorClient client;
    client.init("http://localhost", "test-id", "secret", "100");
    client.start();

    std::vector<AnchorClient::CallEvent::Type> events;
    std::mutex evMu;
    std::atomic<int> count{0};

    client.setEventCallback([&](const AnchorClient::CallEvent& ev) {
        std::lock_guard<std::mutex> lk(evMu);
        events.push_back(ev.type);
        count++;
    });

    std::string ownLeg;
    EXPECT_TRUE(client.makeCall("200", &ownLeg));
    EXPECT_EQ(ownLeg, "mock-part-123");

    // Wait up to 500 ms for both Ringing + Answered events.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (count.load() < 2 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

    std::lock_guard<std::mutex> lk(evMu);
    ASSERT_GE(events.size(), 2u);
    EXPECT_EQ(events[0], AnchorClient::CallEvent::Ringing);
    EXPECT_EQ(events[1], AnchorClient::CallEvent::Answered);
}

// ── Audio loopback ────────────────────────────────────────────────────────────

TEST(LoopbackAnchorClient, WriteAudioLoopsBackThroughCallback) {
    LoopbackAnchorClient client;
    client.init("", "", "", "100");
    client.start();

    std::vector<int16_t> received;
    std::atomic<bool> gotAudio{false};
    client.registerAudioRxCallback([&](std::string_view /*id*/, const int16_t* s, size_t n) {
        received.assign(s, s + n);
        gotAudio = true;
    });

    const int16_t input[] = {100, 200, 300};
    client.writeAudio("mock-part-123", input, 3);

    EXPECT_TRUE(gotAudio.load());
    ASSERT_EQ(received.size(), 3u);
    EXPECT_EQ(received[0], 100);
    EXPECT_EQ(received[1], 200);
    EXPECT_EQ(received[2], 300);
}

TEST(LoopbackAnchorClient, WriteAudioFailsWhenStopped) {
    LoopbackAnchorClient client;
    client.init("", "", "", "100");
    client.start();
    client.stop();

    const int16_t dummy[] = {1};
    EXPECT_FALSE(client.writeAudio("any", dummy, 1));
}

// ── dropCall ──────────────────────────────────────────────────────────────────

TEST(LoopbackAnchorClient, DropCallDeliversDroppedEvent) {
    LoopbackAnchorClient client;
    client.init("", "", "", "100");
    client.start();

    std::atomic<bool> gotDrop{false};
    client.setEventCallback([&](const AnchorClient::CallEvent& ev) {
        if (ev.type == AnchorClient::CallEvent::Dropped)
            gotDrop = true;
    });

    std::string ownLeg;
    client.makeCall("200", &ownLeg);
    EXPECT_TRUE(client.dropCall(ownLeg));

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    while (!gotDrop.load() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

    EXPECT_TRUE(gotDrop.load());
}
