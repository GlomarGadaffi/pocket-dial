// Test-side socket header for the host suite (#1136).
//
// One include for the BSD socket names the tests use: <arpa/inet.h> and its
// siblings on POSIX, Winsock2 on Windows. Test-only. Product code keeps its own
// _WIN32 paths. WSAStartup is done once per process by WinsockInit.cpp.
#pragma once

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
