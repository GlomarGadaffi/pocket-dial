#include "FactoryReset.hpp"

#include "CoreDumpStore.hpp"
#include "EmailConfigStore.hpp"
#include "SipSecretStore.hpp"

namespace FactoryReset
{
	bool eraseStoredSecrets()
	{
		bool ok = true;
		// save() always replaces every field -- its documented contract; the
		// "empty means keep" policy belongs to the HTTP route, not the store --
		// so a default Config overwrites smtp_pass, gsa_key and smtp_ca_pem.
		// Same mechanism the route already uses for TrunkConfigStore.
		ok &= EmailConfigStore::save(EmailConfigStore::Config{});
		ok &= SipSecretStore::clearAll();
		// Erased unconditionally, with no query() first: before #405's cache,
		// query() is itself a deep flash probe, and this runs on a 4 KB
		// connection thread. Its result is NOT folded into `ok`: it fails
		// legitimately on a board whose partition table predates #382 (no
		// coredump partition at all), which is not a failed reset. erase()
		// invalidates CoreDumpStore's own cached Info/Summary.
		(void)CoreDumpStore::erase();
		return ok;
	}
}
