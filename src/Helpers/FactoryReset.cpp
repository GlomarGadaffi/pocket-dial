#include "FactoryReset.hpp"

#include "CoreDumpStore.hpp"
#include "EmailConfigStore.hpp"
#include "SipSecretStore.hpp"

namespace FactoryReset
{
	bool eraseStoredSecrets()
	{
		bool ok = true;
		// clear(), not save(Config{}): erasing each key does not depend on a
		// zero-length nvs_set_blob succeeding for gsa_key, and save()'s chain
		// would stop at the first failure with the private key still in flash.
		ok &= EmailConfigStore::clear();
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
