#pragma once

// FactoryReset -- the stored secrets HttpServer::sendApiFactoryReset() did not
// reach on its own (issue #363).
//
// That route erases key by key and store by store, never a namespace wipe, so a
// store nobody names survives a reset in plaintext flash. Enumerated from every
// persisted secret in the tree (nvs_set_* of a credential; see #363's PR):
//
//   already erased by the route itself:
//     AdminAuth (admin/owner password hashes, DTMF PIN)  AdminAuth::clearCredential()
//     DeviceConfig (ap_psk)                              DeviceConfig::clearAll()
//     TrunkConfigStore (trunk_pass)                      TrunkConfigStore::save({})
//     TelephonyApiConfig ("tapicfg" client secret)       clearAllTelephonyConfig()
//     Wi-Fi STA password (radio builds)                  the POCKETDIAL_HAS_WIFI block
//
//   NOT reached until this function:
//     EmailConfigStore: smtp_pass, gsa_key (a Google service-account PRIVATE KEY),
//                       smtp_ca_pem, plus smtp_user/host/from/to ("pbxcfg")
//     SipSecretStore:   every extension's digest HA1 ("sipauth")
//     CoreDumpStore:    the last panic's dump -- a copy of task stacks, which can
//                       hold any of the above in the clear
//
// Kept out of HttpServer.cpp on purpose, so the route's only change is one call
// (the HTTP layer is being restructured under #410).
namespace FactoryReset
{
	// Erases every store listed as "NOT reached" above. Returns false if any
	// erase failed; it still attempts all of them.
	bool eraseStoredSecrets();
}
