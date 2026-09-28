#include "DnsServer.hpp"
#include "UdpRcvBuf.hpp"   // Issue #496 / #509 review
#include <cstring>
#include <errno.h>
#include <sys/param.h>
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "esp_log.h"

static const char* TAG = "dns_server";

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DnsAnswerHeader {
    uint16_t name_ptr;
    uint16_t type;
    uint16_t class_type;
    uint32_t ttl;
    uint16_t rdlength;
};
#pragma pack(pop)

DnsServer::DnsServer()
    : _resolvedIp("192.168.4.1"), _taskHandle(nullptr), _socketFd(-1), _running(false),
      _exitSem(xSemaphoreCreateBinary()) {}

DnsServer::~DnsServer() {
    stop();
    if (_exitSem) {
        vSemaphoreDelete(_exitSem);
        _exitSem = nullptr;
    }
}

bool DnsServer::start(const std::string& resolvedIp) {
    if (_running.load(std::memory_order_acquire)) return true;

    _resolvedIp = resolvedIp;   // read once by dns_task at startup (after task create)
    _running.store(true, std::memory_order_release);
    // Drain any stale exit signal left by a previous run so stop()'s join is honest.
    if (_exitSem) xSemaphoreTake(_exitSem, 0);

    BaseType_t ret = xTaskCreatePinnedToCore(&DnsServer::dns_task, "dns_task", 4096, this, 5, &_taskHandle, 0);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create DNS task");
        _running.store(false, std::memory_order_release);
        return false;
    }
    _taskStarted = true;
    return true;
}

void DnsServer::stop() {
    bool wasRunning = _running.exchange(false, std::memory_order_acq_rel);

    // Close the socket to unblock a parked recvfrom() immediately. exchange() makes
    // the close single-owner: whichever of stop()/dns_task gets the real fd closes
    // it once; the other gets -1 and skips, so there is no double close.
    int fd = _socketFd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }

    // Join dns_task before returning so a caller that destroys this object right
    // after stop() cannot race a still-running task touching our members (UAF).
    // The ~1 s cap backstops a wedged task. Only wait if a task was actually created.
    if (_taskStarted && _exitSem) {
        xSemaphoreTake(_exitSem, pdMS_TO_TICKS(1000));
        _taskStarted = false;
    }
    _taskHandle = nullptr;
    if (wasRunning) {
        ESP_LOGI(TAG, "DNS server stopped.");
    }
}

void DnsServer::dns_task(void* pvParameters) {
    DnsServer* self = static_cast<DnsServer*>(pvParameters);
    ESP_LOGI(TAG, "DNS server task started resolving to %s", self->_resolvedIp.c_str());

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53); // Standard DNS port

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        self->_running.store(false, std::memory_order_release);
        if (self->_exitSem) xSemaphoreGive(self->_exitSem);
        vTaskDelete(NULL);
        return;
    }
    self->_socketFd.store(sock, std::memory_order_release);

    // Bounded recv timeout (M-2): lets the loop observe _running even if the socket
    // close in stop() does not unblock recvfrom() on this lwIP build, and bounds a
    // silent sender. Mirrors UdpServer / RtpReceiver's 500 ms SO_RCVTIMEO pattern.
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 500000;   // 500 ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Issue #496 / #509 review: with IPv4 reassembly on, one queued datagram can
    // be ~14.8 KB. A DNS query is one small packet; cap the queue (UdpRcvBuf.hpp).
    if (!udprcvbuf::set(sock, udprcvbuf::kDns)) {
        ESP_LOGE(TAG, "SO_RCVBUF(%d) failed: DNS receive queue is UNBOUNDED", udprcvbuf::kDns);
    }

    // Standard BSD-sockets idiom: bind()/recvfrom() take `struct sockaddr *`,
    // and casting the concrete `sockaddr_in` up to it is how every sockets API
    // is used in C/C++ -- not the raw-memory reinterpretation dangerousTypeCast
    // is built to catch. False positive.
    // cppcheck-suppress dangerousTypeCast
    int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        int fd = self->_socketFd.exchange(-1, std::memory_order_acq_rel);
        if (fd != -1) close(fd);
        self->_running.store(false, std::memory_order_release);
        if (self->_exitSem) xSemaphoreGive(self->_exitSem);
        vTaskDelete(NULL);
        return;
    }

    uint8_t rx_buffer[512];
    uint8_t tx_buffer[512];

    // Setup client address struct
    struct sockaddr_in source_addr;
    socklen_t socklen = sizeof(source_addr);

    // Parse the target IP address string once
    uint8_t ip_bytes[4] = {192, 168, 4, 1};
    int parsed_ip[4];
    if (sscanf(self->_resolvedIp.c_str(), "%d.%d.%d.%d", &parsed_ip[0], &parsed_ip[1], &parsed_ip[2], &parsed_ip[3]) == 4) {
        for (int i = 0; i < 4; i++) {
            ip_bytes[i] = static_cast<uint8_t>(parsed_ip[i]);
        }
    }

    while (self->_running.load(std::memory_order_acquire)) {
        // Same BSD-sockets idiom as the bind() above -- recvfrom() also takes
        // `struct sockaddr *`. False positive.
        // cppcheck-suppress dangerousTypeCast
        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer), 0, (struct sockaddr *)&source_addr, &socklen);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;   // SO_RCVTIMEO expiry: re-check _running and loop
            }
            if (self->_running.load(std::memory_order_acquire)) {
                ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            }
            break;          // real error, or socket closed by stop()
        }

        // Process only if it looks like a valid DNS query (at least a header)
        if (len < (int)sizeof(DnsHeader)) {
            continue;
        }

        DnsHeader* rx_header = reinterpret_cast<DnsHeader*>(rx_buffer);
        uint16_t flags = ntohs(rx_header->flags);
        uint16_t qdcount = ntohs(rx_header->qdcount);

        // If it's a query (not a response) and has at least one question
        if ((flags & 0x8000) == 0 && qdcount > 0) {
            // Replicate header for response
            DnsHeader* tx_header = reinterpret_cast<DnsHeader*>(tx_buffer);
            tx_header->id = rx_header->id;
            tx_header->flags = htons(0x8400); // Standard response, Auth, No error
            tx_header->qdcount = htons(qdcount);
            tx_header->ancount = htons(1); // One answer response (simplification: respond to first query only)
            tx_header->nscount = 0;
            tx_header->arcount = 0;

            // Copy queries section from rx to tx
            // Finding the end of queries section
            int query_offset = sizeof(DnsHeader);

            // Re-read questions section to find boundaries safely
            bool valid_query = true;
            for (int q = 0; q < qdcount; q++) {
                // Parse labels until null byte (0)
                while (query_offset < len && rx_buffer[query_offset] != 0) {
                    uint8_t label_len = rx_buffer[query_offset];
                    // Label offset sanity check
                    if (query_offset + 1 + label_len >= len) {
                        valid_query = false;
                        break;
                    }
                    query_offset += 1 + label_len;
                }

                if (!valid_query) break;
                query_offset += 1; // skip null byte

                // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
                if (query_offset + 4 > len) {
                    valid_query = false;
                    break;
                }
                query_offset += 4;
            }

            if (!valid_query || query_offset > (int)sizeof(tx_buffer)) {
                continue;
            }

            // Copy whole queries block to output buffer
            memcpy(tx_buffer + sizeof(DnsHeader), rx_buffer + sizeof(DnsHeader), query_offset - sizeof(DnsHeader));

            // Append standard A answer record mapping back to queried name
            DnsAnswerHeader answer;
            answer.name_ptr = htons(0xC00C); // pointer to domain name in query (offset 12)
            answer.type = htons(1);          // A record
            answer.class_type = htons(1);    // IN class
            answer.ttl = htonl(10);          // 10s lease
            answer.rdlength = htons(4);      // IPv4 length (4 bytes)

            int tx_len = query_offset;
            if (tx_len + (int)sizeof(DnsAnswerHeader) + 4 <= (int)sizeof(tx_buffer)) {
                memcpy(tx_buffer + tx_len, &answer, sizeof(DnsAnswerHeader));
                tx_len += sizeof(DnsAnswerHeader);
                memcpy(tx_buffer + tx_len, ip_bytes, 4);
                tx_len += 4;

                // Send back reply to source address
                int sent = sendto(sock, tx_buffer, tx_len, 0,
                                  reinterpret_cast<struct sockaddr *>(&source_addr),
                                  socklen);
                if (sent < 0) {
                    ESP_LOGE(TAG, "DNS sendto failed: errno %d", errno);
                }
            }
        }
    }

    // This task owns the socket close unless stop() raced in first; exchange() makes
    // it single-owner so the fd is closed exactly once.
    int fd = self->_socketFd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) {
        close(fd);
    }
    self->_running.store(false, std::memory_order_release);
    ESP_LOGI(TAG, "DNS server task completed.");
    // LAST access to `self`: signal stop()/destructor that we have fully exited.
    if (self->_exitSem) xSemaphoreGive(self->_exitSem);
    vTaskDelete(NULL);
}
