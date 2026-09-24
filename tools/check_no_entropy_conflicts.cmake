# Issue #420: post-link guard for the Ethernet transports.
#
# esp_main_eth*.cpp call bootloader_random_enable() at boot and LEAVE the SAR
# ADC entropy source on, so esp_random() -- every security-relevant number on
# the board, TLS included -- is a true RNG. ESP-IDF's random.rst requires that
# source to be disabled before the ADC, the RF subsystem (Wi-Fi/BT) or, on the
# classic ESP32, I2S is used. Nothing on these transports uses any of them
# today; this fails the BUILD if something ever links one in, because the
# failure it prevents is silent (a garbled ADC reading or weakened randomness,
# never a crash).
#
# Checks the FINAL ELF's defined symbols, so it also catches a driver pulled in
# transitively by some other component, which a REQUIRES check would miss.
#
# Invoked from the root CMakeLists.txt as:
#   cmake -DNM=<nm> -DELF=<elf> -DCHECK_I2S=<ON|OFF> -P check_no_entropy_conflicts.cmake

if(NOT NM OR NOT ELF)
    message(FATAL_ERROR "check_no_entropy_conflicts: NM and ELF must be set")
endif()

execute_process(
    COMMAND "${NM}" --defined-only "${ELF}"
    OUTPUT_VARIABLE symbols
    RESULT_VARIABLE nm_rc)
if(NOT nm_rc EQUAL 0)
    message(FATAL_ERROR "check_no_entropy_conflicts: '${NM}' failed on ${ELF} (${nm_rc})")
endif()

# Entry points of each conflicting driver. Any one of them defined in the image
# means that driver is linked in and may be used.
set(forbidden
    adc_oneshot_new_unit          # esp_adc one-shot
    adc_continuous_new_handle     # esp_adc continuous (DMA)
    adc_cali_create_scheme_curve_fitting
    temperature_sensor_install    # the S3 temperature sensor shares the SAR ADC
    esp_wifi_start                # RF: Wi-Fi
    esp_bt_controller_enable      # RF: Bluetooth
)
if(CHECK_I2S)
    list(APPEND forbidden i2s_new_channel)   # classic ESP32: I2S0 carries the entropy source
endif()

set(found "")
foreach(sym IN LISTS forbidden)
    if(symbols MATCHES "[ \t]${sym}(\r?\n|$)")
        list(APPEND found "${sym}")
    endif()
endforeach()

if(found)
    list(JOIN found ", " found_str)
    message(FATAL_ERROR
        "Issue #420: this Ethernet build leaves the SAR ADC entropy source ON "
        "(esp_main_eth*.cpp, bootloader_random_enable), but it now links: ${found_str}. "
        "ESP-IDF random.rst requires bootloader_random_disable() before ADC, RF "
        "(and on the classic ESP32, I2S) use. Either keep that driver off this transport, or change "
        "#420's approach to seed-then-disable -- do not just delete this check.")
endif()
