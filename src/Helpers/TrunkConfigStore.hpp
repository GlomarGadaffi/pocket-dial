#ifndef TRUNK_CONFIG_STORE_HPP
#define TRUNK_CONFIG_STORE_HPP

// TrunkConfigStore: persisted ITSP SIP trunk settings (#164's configuration
// surface). NVS namespace "pbxcfg", shared with the rest of the PBX config
// tables for the reasons PbxPersist.hpp/DeviceConfig.hpp give -- this is not a
// new namespace. Keys (all within NVS's 15-character limit):
//
//   trunk_host, trunk_port      the registrar / carrier server
//   trunk_proxy, trunk_pxport   the outbound proxy, when the carrier uses one
//   trunk_from                  the From identity (usually the main DID)
//   trunk_cid                   outbound caller ID; empty = use trunk_from
//   trunk_authid                digest authentication ID ("SIP ID")
//   trunk_pass                  digest password
//   trunk_en                    enabled flag
//
// Host builds: in-memory only for the process's lifetime, exactly as
// AdminAuth.cpp/DeviceConfig.cpp/EmailConfigStore.cpp do it -- there is no NVS
// on the desktop build, and the in-memory struct IS the store, so the host
// tests exercise the full load/save round trip without a device.
//
// SECRET HANDLING. `pass` is a real plaintext secret and is treated the way
// EmailConfigStore treats smtp_pass: load() returns it because the engine needs
// the actual value to authenticate, but the GET route MUST NOT put it in a
// response body -- it reports only a `hasPassword` boolean. That is the #207
// bug class this project has been bitten by twice; TrunkConfigHttp_test.cpp pins it.
//
// Why plaintext and not a hash: SIP digest is challenge-response, so an
// outbound client must be able to recompute MD5(HA1:nonce:...) at call time.
// SipSecretStore gets to persist HA1 instead because it authenticates INBOUND
// registrations against a realm we choose and fix ("pocketdial"); an outbound
// trunk is challenged with the CARRIER's realm, which is unknown until the 401
// arrives and can change under us, so a precomputed HA1 is useless here.
//
// AT-REST PROTECTION IS THE PLATFORM'S JOB: on ESP these land in NVS in
// plaintext unless flash encryption + NVS encryption are enabled. Do NOT
// describe this store as "secure storage" anywhere unless that platform
// feature is actually on -- the same statement TelephonyApiConfig.hpp makes.

#include <cstdint>
#include <string>

namespace TrunkConfigStore
{

	struct Config
	{
		std::string host;              // registrar / carrier server (FQDN or IP)
		uint16_t    port = 5060;

		std::string proxyHost;         // outbound proxy; empty = none
		uint16_t    proxyPort = 5060;

		std::string fromUser;          // From identity, usually the main DID
		std::string callerId;          // outbound CLI; empty = use fromUser
		std::string authUser;          // digest auth ID; empty = use fromUser
		std::string pass;              // digest password

		bool enabled = false;
	};

	// The current configuration. Never fails outright -- an absent or corrupt
	// stored value leaves that field at Config{}'s default, the same convention
	// as DeviceConfig's flash-seed reader and EmailConfigStore::load().
	Config load();

	// Persists `cfg` verbatim, including `pass`. The "an empty submitted
	// password means leave the stored one alone" policy belongs to the HTTP
	// route, which must load() first and merge -- not to this function, which
	// always replaces. Returns false if persistence failed (NVS open/write/
	// commit error), in which case the in-memory cache is left at its previous
	// value rather than diverging from flash.
	bool save(const Config& cfg);

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Host-only: reset the in-memory cache to defaults and clear the "loaded"
	// flag so the next load() starts clean instead of returning a previous
	// test's leftovers. Every test in the binary otherwise shares the one
	// process-lifetime cache -- same reasoning as
	// EmailConfigStore::resetForTest() and AdminAuth::clearCredential().
	void resetForTest();
#endif

} // namespace TrunkConfigStore

#endif // TRUNK_CONFIG_STORE_HPP
