#ifndef POCKETDIAL_FIRMWARE_INFO_HPP
#define POCKETDIAL_FIRMWARE_INFO_HPP

// FirmwareInfo: which build is this? (issue #411)
//
// One source for every place the firmware identifies itself -- /api/status,
// the boot banner -- so they cannot disagree. The stamp is decided once, at
// configure time, by cmake/FirmwareVersion.cmake:
//
//   * on the device it is ESP-IDF's PROJECT_VER, read back from the app
//     descriptor (esp_app_get_description()), i.e. from the image itself;
//   * on host builds it is the same string, passed in as the
//     POCKETDIAL_FW_VERSION compile definition.
//
// So a board's /api/status and the `git describe` of the commit it was built
// from match, which is what TEST_HARNESS.md §5.3's board-provenance check and
// tests/run.py compare. That used to be impossible: the version was always
// "1" because git failed inside CI's build container.
//
// Every accessor returns a pointer to static storage (the app descriptor on
// the device, string literals on host): no allocation, safe to call from any
// task at any time, including before the scheduler starts.

namespace FirmwareInfo
{
	// e.g. "v1.5.0-beta.2-93-g98cc830" or, for an uncommitted tree,
	// "...-dirty". "unknown" only if the build had no git at all -- never
	// ESP-IDF's "1" fallback.
	const char* version();

	// The ESP-IDF version the image was built with, e.g. "v6.0.1". "host" on
	// host builds.
	const char* idfVersion();

	// Build date and time, as the compiler saw them ("Sep 24 2026", "06:55:56").
	const char* buildDate();
	const char* buildTime();
}

#endif // POCKETDIAL_FIRMWARE_INFO_HPP
