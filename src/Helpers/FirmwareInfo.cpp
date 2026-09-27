#include "FirmwareInfo.hpp"

#if defined(ESP_PLATFORM)

// On the device, read everything back from the app descriptor: the version
// the running IMAGE carries, not a string compiled into this one file. A
// stale object file cannot then misreport the image it ended up in.
#include "esp_app_desc.h"

namespace FirmwareInfo
{
	const char* version()    { return esp_app_get_description()->version; }
	const char* idfVersion() { return esp_app_get_description()->idf_ver; }
	const char* buildDate()  { return esp_app_get_description()->date; }
	const char* buildTime()  { return esp_app_get_description()->time; }
}

#else

// Host builds: the same stamp, handed in by cmake/FirmwareVersion.cmake. A
// build that forgot to pass it fails here, loudly, instead of quietly
// reporting a version nobody chose.
#ifndef POCKETDIAL_FW_VERSION
	#error "POCKETDIAL_FW_VERSION is not defined: include cmake/FirmwareVersion.cmake and add it as a compile definition (see tests/CMakeLists.txt)"
#endif

namespace FirmwareInfo
{
	const char* version()    { return POCKETDIAL_FW_VERSION; }
	const char* idfVersion() { return "host"; }
	const char* buildDate()  { return __DATE__; }
	const char* buildTime()  { return __TIME__; }
}

#endif
