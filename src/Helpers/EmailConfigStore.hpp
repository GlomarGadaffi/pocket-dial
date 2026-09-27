#ifndef EMAIL_CONFIG_STORE_HPP
#define EMAIL_CONFIG_STORE_HPP

// EmailConfigStore: issue #159's persisted SMTP configuration. NVS namespace
// "pbxcfg" (shared with the rest of the PBX config tables -- see
// PbxPersist.hpp/DeviceConfig.hpp for why this namespace, not a new one),
// keys exactly as the issue lists: smtp_host, smtp_port, smtp_mode,
// smtp_auth, smtp_user, smtp_pass, smtp_from, smtp_to, gsa_email, gsa_key
// -- plus two natural extensions the issue's scope section calls for but
// does not name a key for: smtp_insecure (the documented LAN-relay-only
// toggle) and smtp_ca_pem (the optional custom server CA).
//
// gsa_key (the service-account private key, PEM) and smtp_ca_pem are stored
// as NVS BLOBS, not via nvs_set_str -- both can exceed nvs_set_str's ~4000
// byte cap (a real-world RSA private key PEM plus a CA chain can both get
// close to or past that).
//
// Host builds: in-memory only for the process's lifetime, same pattern as
// AdminAuth.cpp/DeviceConfig.cpp -- there is no NVS on the desktop build, and
// the in-memory struct IS the store, so EmailHttp_test.cpp can exercise the
// full load/save round trip without a device.
//
// Secrets (pass, gsaKey) are never re-serialized to the caller by anything
// in this file -- load() returns them because SmtpClient needs the real
// values to authenticate, but HttpServer's GET /api/email handler MUST NOT
// forward cfg.pass/cfg.gsaKey to the response body; it reports only
// hasPassword/hasGsaKey booleans (see EmailHttp_test.cpp's "never echoes
// secrets, even authenticated" case, the #207 class of bug this project has
// been bitten by twice already).

#include <cstdint>
#include <string>

namespace EmailConfigStore
{

	struct Config
	{
		std::string host;
		uint16_t port = 587;
		std::string mode = "starttls";  // "tls" | "starttls" | "plain"
		std::string auth = "none";      // "none" | "plain" | "login" | "xoauth2-sa"
		std::string user;
		std::string pass;               // AUTH PLAIN/LOGIN secret
		std::string from;
		std::string to;                 // default recipient(s), comma-separated
		std::string gsaEmail;           // service-account email (xoauth2-sa)
		std::string gsaKey;             // service-account private key, PEM
		bool insecureSkipVerify = false; // LAN-relay-only; default OFF
		std::string caPem;               // optional custom server CA; empty = esp_crt_bundle default
	};

	// The current configuration. Never fails outright -- an absent/corrupt
	// stored value leaves that field at Config{}'s default, same convention
	// as DeviceConfig's flash-seed reader.
	Config load();

	// Persists `cfg` verbatim (every field, including pass/gsaKey) -- the
	// "empty submitted value means leave the stored secret unchanged" policy
	// belongs to the HTTP route (it must load() first, merge, then save()),
	// not to this function, which always replaces. Returns false if
	// persistence failed (NVS open/write/commit error); the in-memory cache
	// this process would otherwise read back from is left at its previous
	// value in that case.
	bool save(const Config& cfg);

	// Erase every stored field (the factory-reset path, #363) and reset the
	// cache to Config{}. Unlike save(Config{}) it does not depend on writing a
	// zero-length blob, and it attempts every key even after a failure.
	bool clear();

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Host-only: resets the in-memory cache to Config{}'s defaults and clears
	// the "loaded" flag, so the next load() re-reads (finding nothing, on
	// host) instead of returning a previous test's leftover state. Without
	// this every test in the binary would share the one process-lifetime
	// g_cache -- same reasoning as AdminAuth::clearCredential(). No-op
	// symbol does not exist on-device: there is nothing to reset in NVS from
	// a running firmware, and no test calls this there.
	void resetForTest();
#endif

} // namespace EmailConfigStore

#endif
