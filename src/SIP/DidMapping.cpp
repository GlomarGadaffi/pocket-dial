#include "DidMapping.hpp"

#include "E164.hpp"

#include <cstdio>
#include <cstring>
#include <cstdlib>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Persisted in a DEDICATED NVS namespace ("didmap") so a factory-reset of
	// the PBX config ("pbxcfg") or the Telephony-API credential table
	// ("tapicfg") never collaterally wipes this table (or vice versa).
	#include "nvs_flash.h"
	#include "nvs.h"
#else
	// Host fallback: a plaintext key=value file created with 0600 permissions
	// (same pattern as TelephonyApiConfig — DIDs/extensions aren't secrets, but
	// there is no reason to make the file world-readable either).
	#include <sys/stat.h>
	#include <sys/types.h>
	#include <fcntl.h>
	#if !defined(_WIN32)
		#include <unistd.h>
	#endif
	#include <fstream>
	#include <sstream>
#endif

namespace
{
	constexpr const char* kNvsNamespace = "didmap";

	// NVS keys are capped at 15 chars; "m0did".."m7ext" (default 8 slots) all
	// fit comfortably, and so does any single-digit-index cap override.
	void slotKey(char* out, size_t outLen, size_t idx, const char* field)
	{
		std::snprintf(out, outLen, "m%u%s", static_cast<unsigned>(idx), field);
	}
}

bool DidMapping::fieldValid(const std::string& s)
{
	// Empty/too-long are checked by callers with more specific error
	// messages; this only guards the host store's line/'='-delimited format
	// (and, cheaply, the NVS string too) against an embedded control
	// character or a stray '=' corrupting the table on the next load().
	for (char c : s)
	{
		if (c == '\r' || c == '\n' || c == '=')
		{
			return false;
		}
	}
	return true;
}

bool DidMapping::sameDid(const std::string& a, const std::string& b)
{
	// Exact string identity first, and unconditionally. It is the only thing
	// that can match a DID which is not a telephone number at all — a
	// hand-edited store, or an entry written by some future build with a wider
	// field charset, must stay findable by list()/removeMapping() rather than
	// becoming an unremovable row. pbx::e164SameNumber() returns false for
	// anything it cannot normalize, so without this line such an entry would
	// be stranded in the table forever.
	if (a == b)
	{
		return true;
	}

	// Then E.164 equivalence (Issue #165): the DID the carrier reports and the
	// DID the operator typed name the same line even when they are written
	// differently ("+15551234567" vs "(555) 123-4567"). See E164.hpp for the
	// exact rule and its one accepted false positive.
	return pbx::e164SameNumber(a, b);
}

size_t DidMapping::findIndex(const std::string& did) const
{
	for (size_t i = 0; i < _count; ++i)
	{
		if (sameDid(_entries[i].did, did))
		{
			return i;
		}
	}
	return kMaxMappings;
}

std::string DidMapping::setMapping(const std::string& did, const std::string& extension)
{
	if (did.empty())
	{
		return "DID required";
	}
	if (extension.empty())
	{
		return "Extension required";
	}
	if (did.size() > kMaxFieldLen || extension.size() > kMaxFieldLen)
	{
		return "Field too long";
	}
	if (!fieldValid(did) || !fieldValid(extension))
	{
		return "Field contains a control character";
	}

	const size_t idx = findIndex(did);
	if (idx < _count)
	{
		// Existing DID: update in place. Never consumes a slot, so this can
		// succeed even when every OTHER slot is taken. Adopt the caller's
		// rendering of `did` too, not just the extension -- findIndex()
		// matched on E.164 equivalence (Issue #165), so a re-set can arrive
		// as a different spelling of the same line ("+12025550123" over a
		// stored "(202) 555-0123"), and list()/the dashboard should reflect
		// what the operator most recently typed rather than whatever was
		// stored first (Issue #243).
		_entries[idx].did = did;
		_entries[idx].extension = extension;
		return persist();
	}
	if (_count >= kMaxMappings)
	{
		return "DID mapping table full";
	}
	_entries[_count].did = did;
	_entries[_count].extension = extension;
	++_count;
	return persist();
}

std::string DidMapping::removeMapping(const std::string& did)
{
	const size_t idx = findIndex(did);
	if (idx >= _count)
	{
		return "";  // idempotent: nothing to remove, nothing to persist
	}
	// Compact: shift everything after idx down one so list()/persist() never
	// see a hole. Order-preserving for the surviving entries.
	for (size_t i = idx; i + 1 < _count; ++i)
	{
		_entries[i] = _entries[i + 1];
	}
	--_count;
	_entries[_count] = Entry{};  // clear the now-unused tail slot
	return persist();
}

std::string DidMapping::clearAll()
{
	// Same reset-then-persist shape as load()'s in-memory reset, but persisted:
	// an empty table written to the backing store, same as persist()'s own
	// "i >= _count" branch already does for every never-used slot.
	_count = 0;
	for (auto& e : _entries) { e = Entry{}; }
	return persist();
}

std::vector<DidMapping::Entry> DidMapping::list() const
{
	return std::vector<Entry>(_entries, _entries + _count);
}

std::string DidMapping::extensionForDid(const std::string& did) const
{
	if (did.empty())
	{
		return "";
	}
	const size_t idx = findIndex(did);
	return (idx < _count) ? _entries[idx].extension : "";
}

// ── Persistence backends ──────────────────────────────────────────────────────

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

void DidMapping::load()
{
	_count = 0;
	for (auto& e : _entries) { e = Entry{}; }

	nvs_handle_t h;
	if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK)
	{
		return;  // first boot: empty table stands
	}
	char key[16];
	char buf[kMaxFieldLen + 1];
	for (size_t i = 0; i < kMaxMappings; ++i)
	{
		std::string didStr, extStr;

		slotKey(key, sizeof(key), i, "did");
		size_t len = sizeof(buf);
		std::memset(buf, 0, sizeof(buf));
		if (nvs_get_str(h, key, buf, &len) == ESP_OK && buf[0] != '\0')
		{
			didStr.assign(buf);
		}

		slotKey(key, sizeof(key), i, "ext");
		len = sizeof(buf);
		std::memset(buf, 0, sizeof(buf));
		if (nvs_get_str(h, key, buf, &len) == ESP_OK && buf[0] != '\0')
		{
			extStr.assign(buf);
		}

		// Defensive: skip a partial/empty slot rather than keeping a hole.
		if (!didStr.empty() && !extStr.empty() && _count < kMaxMappings)
		{
			_entries[_count].did = didStr;
			_entries[_count].extension = extStr;
			++_count;
		}
	}
	nvs_close(h);
}

std::string DidMapping::persist()
{
	nvs_handle_t h;
	if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
	{
		return "NVS open failed";
	}
	bool ok = true;
	char key[16];
	for (size_t i = 0; i < kMaxMappings && ok; ++i)
	{
		const bool live = i < _count;
		slotKey(key, sizeof(key), i, "did");
		ok = ok && nvs_set_str(h, key, live ? _entries[i].did.c_str() : "") == ESP_OK;
		slotKey(key, sizeof(key), i, "ext");
		ok = ok && nvs_set_str(h, key, live ? _entries[i].extension.c_str() : "") == ESP_OK;
	}
	ok = ok && nvs_commit(h) == ESP_OK;
	nvs_close(h);
	return ok ? "" : "NVS write failed";
}

#else  // host builds: 0600-permission key=value file

void DidMapping::load()
{
	_count = 0;
	for (auto& e : _entries) { e = Entry{}; }

	std::ifstream f(_storePath);
	if (!f.is_open())
	{
		return;  // no store yet: empty table stands
	}

	// Parsed into per-index scratch first so a hand-edited or short file
	// (missing one half of a pair) can't produce a hole in _entries — only a
	// slot with BOTH fields present makes it into the compacted table below.
	std::string dids[kMaxMappings];
	std::string exts[kMaxMappings];

	std::string line;
	while (std::getline(f, line))
	{
		const size_t eq = line.find('=');
		if (eq == std::string::npos || eq < 4 || line[0] != 'm')
		{
			continue;  // shortest valid key is "m0did"/"m0ext" (5 chars)
		}
		const std::string k = line.substr(0, eq);
		const std::string val = line.substr(eq + 1);

		std::string field;
		if (k.size() > 3 && k.compare(k.size() - 3, 3, "did") == 0) field = "did";
		else if (k.size() > 3 && k.compare(k.size() - 3, 3, "ext") == 0) field = "ext";
		else continue;

		const std::string idxStr = k.substr(1, k.size() - 1 - 3);
		const long idx = std::strtol(idxStr.c_str(), nullptr, 10);
		if (idx < 0 || static_cast<size_t>(idx) >= kMaxMappings)
		{
			continue;
		}
		if (field == "did") dids[static_cast<size_t>(idx)] = val;
		else                exts[static_cast<size_t>(idx)] = val;
	}

	for (size_t i = 0; i < kMaxMappings; ++i)
	{
		if (!dids[i].empty() && !exts[i].empty() && _count < kMaxMappings)
		{
			_entries[_count].did = dids[i];
			_entries[_count].extension = exts[i];
			++_count;
		}
	}
}

std::string DidMapping::persist()
{
#if defined(_WIN32)
	// No POSIX permission model; honest in-memory only (the file would be
	// world-readable). The table still works for the session — same
	// trade-off TelephonyApiConfig::persist() documents for _WIN32.
	return "";
#else
	// Create/truncate with 0600 BEFORE any byte hits the disk.
	const int fd = ::open(_storePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
	{
		return "config file open failed";
	}
	(void)::fchmod(fd, 0600);  // in case the file pre-existed with looser bits

	std::ostringstream out;
	for (size_t i = 0; i < kMaxMappings; ++i)
	{
		const bool live = i < _count;
		out << 'm' << i << "did=" << (live ? _entries[i].did : std::string()) << '\n'
		    << 'm' << i << "ext=" << (live ? _entries[i].extension : std::string()) << '\n';
	}
	const std::string data = out.str();
	const bool ok = ::write(fd, data.data(), data.size()) ==
	                static_cast<ssize_t>(data.size());
	::close(fd);
	return ok ? "" : "config file write failed";
#endif
}

#endif
