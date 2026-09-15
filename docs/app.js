// pocket-dial modern minimal landing page engine

// ==========================================================================
// 1. HARDWARE PROFILES REGISTRY (ASCII & Pinouts)
// ==========================================================================
const HARDWARE_PROFILES = {
    't-eth-elite': {
        title: "LilyGO T-ETH-ELITE S3 (W5500, 802.3af PoE)",
        desc: "The default Ethernet target. An ESP32-S3-WROOM-1 carrier (16 MB flash, 8 MB PSRAM) pairing a W5500 SPI controller with onboard 802.3af PoE and a 40-pin Pi-compatible header. A different board from the T-ETH-Lite \u2014 the pin map is not the same.",
        specs: {
            "Core CPU": "ESP32-S3-WROOM-1",
            "PHY Interface": "W5500 SPI Controller",
            "SPI Host": "SPI2_HOST (FSPI) @ 40 MHz",
            "SCLK Pin": "GPIO 48",
            "MISO Pin": "GPIO 47",
            "MOSI Pin": "GPIO 21",
            "CS Pin": "GPIO 45",
            "INT Pin": "GPIO 14",
            "RST Pin": "Not wired (-1)"
        },
        ascii:
` \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
 \u2502 [RJ45 PoE 802.3af] \u2550\u2550 [W5500 MAC/PHY]
 \u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524
 \u2502 SCLK:48 \u2551 MOSI:21 \u2551 CS:45  \u2551 RST:\u2014
 \u2502 MISO:47 \u2551 INT:14  \u2551 SPI2   \u2551 40MHz
 \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`,
        code:
`// LilyGO T-ETH-ELITE S3 \u2014 the default 'eth' board
// Build with: -D PD_ETH_BOARD=elite   (this is the default)
#define W5500_SCLK_GPIO 48
#define W5500_MISO_GPIO 47
#define W5500_MOSI_GPIO 21
#define W5500_CS_GPIO   45
#define W5500_INT_GPIO  14
#define W5500_RST_GPIO  -1   // not wired; reset via SPI soft command

// 40 MHz is the hardware-verified ceiling here: the Elite's W5500 pins
// route through the GPIO matrix rather than IOMUX, and 80 MHz hard-fails
// at driver install with ESP_ERR_TIMEOUT.`
    },
    't-eth-lite': {
        title: "LilyGO T-ETH-Lite S3 (W5500 via SPI)",
        desc: "Sleek ESP32-S3 board with onboard RJ45 wired SPI Ethernet. The hardware MAC is emulated in software via the W5500 driver over the SPI bus.",
        specs: {
            "Core CPU": "ESP32-S3 Xtensa LX7",
            "PHY Interface": "W5500 SPI Controller",
            "SCLK Pin": "GPIO 10",
            "MISO Pin": "GPIO 11",
            "MOSI Pin": "GPIO 12",
            "CS Pin": "GPIO 9",
            "INT Pin": "GPIO 13",
            "RST Pin": "GPIO 14"
        },
        ascii: 
` ┌──────────────────────────────────┐
 │ [ESP32-S3] ════ [W5500 SPI Controller]
 ├──────────────────────────────────┤
 │ SCLK:10 ║ MOSI:12 ║ CS:09  ║ RST:14
 │ MISO:11 ║ INT:13  ║ VCC:5V ║ GND
 └──────────────────────────────────┘`,
        code: 
`// LilyGO T-ETH-Lite S3 Pinout Config
#define ETH_MISO_PIN   11
#define ETH_MOSI_PIN   12
#define ETH_SCLK_PIN   10
#define ETH_CS_PIN      9
#define ETH_INT_PIN    13
#define ETH_RST_PIN    14

SPI.begin(ETH_SCLK_PIN, ETH_MISO_PIN, ETH_MOSI_PIN);
ETH.begin(ETH_PHY_W5500, 1, ETH_CS_PIN, ETH_INT_PIN, ETH_RST_PIN, SPI);`
    },
    't-poe-pro': {
        title: "LilyGO T-POE-Pro (LAN8720 via RMII)",
        desc: "High-performance ESP32 board with direct RMII PHY support and Power-over-Ethernet (PoE). Uses standard ESP32 hardware MAC for native speeds.",
        specs: {
            "Core CPU": "ESP32-WROVER-E LX6",
            "PHY Interface": "LAN8720 RMII Controller",
            "PHY Address": "0",
            "MDC Pin": "GPIO 23",
            "MDIO Pin": "GPIO 18",
            "Power Pin": "GPIO 5 (Active Low)",
            "Ref Clock": "GPIO 17 Output (50MHz)",
            "SPI Mode": "Disabled (RMII Native)"
        },
        ascii:
` ┌──────────────────────────────────┐
 │ [ESP32-WROVER] ═ [LAN8720 RMII Native]
 ├──────────────────────────────────┤
 │ MDC:23 ║ MDIO:18 ║ POWER:05 (RESET)
 │ CLK_MODE: ETH_CLOCK_GPIO17_OUT
 └──────────────────────────────────┘`,
        code:
`// LilyGO T-POE-Pro LAN8720 Config
#define ETH_MDC_PIN    23
#define ETH_MDIO_PIN   18
#define ETH_POWER_PIN   5
#define ETH_PHY_ADDR    0
#define ETH_CLK_MODE   ETH_CLOCK_GPIO17_OUT

ETH.begin(ETH_PHY_LAN8720, ETH_PHY_ADDR, ETH_MDC_PIN, 
          ETH_MDIO_PIN, ETH_POWER_PIN, ETH_CLK_MODE);`
    },
    'waveshare-poe': {
        title: "Waveshare ESP32-S3-ETH (W5500 SPI)",
        desc: "Compact Waveshare S3 development board featuring PoE Ethernet and custom pin routing for general SPI controllers.",
        specs: {
            "Core CPU": "ESP32-S3 Xtensa LX7",
            "PHY Interface": "W5500 SPI Controller",
            "SCLK Pin": "GPIO 12",
            "MISO Pin": "GPIO 13",
            "MOSI Pin": "GPIO 11",
            "CS Pin": "GPIO 10",
            "INT Pin": "GPIO 14",
            "RST Pin": "Disabled (-1)"
        },
        ascii:
` ┌──────────────────────────────────┐
 │ [ESP32-S3] ════ [W5500 SPI PoE]
 ├──────────────────────────────────┤
 │ SCLK:12 ║ MOSI:11 ║ CS:10  ║ RST:-1
 │ MISO:13 ║ INT:14  ║ VCC:5V ║ GND
 └──────────────────────────────────┘`,
        code:
`// Waveshare W5500 SPI Pin Configuration
#define ETH_MISO_PIN   13
#define ETH_MOSI_PIN   11
#define ETH_SCLK_PIN   12
#define ETH_CS_PIN     10
#define ETH_INT_PIN    14
#define ETH_RST_PIN    -1

SPI.begin(ETH_SCLK_PIN, ETH_MISO_PIN, ETH_MOSI_PIN);
ETH.begin(ETH_PHY_W5500, 1, ETH_CS_PIN, ETH_INT_PIN, ETH_RST_PIN, SPI);`
    },
    'standard-wifi': {
        title: "CYD / ESP32 Standard Wi-Fi AP (Wireless)",
        desc: "Classic ESP32 or Cheap Yellow Display (CYD) board wireless SoftAP. The server spins up an isolated DHCP server, providing router-less SIP calls.",
        specs: {
            "Core CPU": "ESP32 / ESP32-S3 LX7",
            "PHY Interface": "802.11 b/g/n Wi-Fi",
            "SoftAP SSID": "esp32-sipserver",
            "SoftAP Auth": "Open / No Password",
            "IP Address": "192.168.4.1",
            "Subnet Mask": "255.255.255.0",
            "DHCP Clients": "Up to 4 Extensions",
            "SPI Mode": "Unused (Wireless RF)"
        },
        ascii:
` ┌──────────────────────────────────┐
 │ [ESP32 RF] ═ ═ ═ ═ [esp32-sipserver AP]
 ├──────────────────────────────────┤
 │ Gateway: 192.168.4.1             
 │ Client Leases: 192.168.4.2 -> .5 
 └──────────────────────────────────┘`,
        code:
`// WiFi SoftAP Initialization Configuration
#include <WiFi.h>

const char* ssid = "esp32-sipserver";
IPAddress local_ip(192, 168, 4, 1);
IPAddress gateway(192, 168, 4, 1);
IPAddress subnet(255, 255, 255, 0);

WiFi.softAPConfig(local_ip, gateway, subnet);
WiFi.softAP(ssid);`
    }
};

// ==========================================================================
// 2. QUICKSTART OS INSTRUCTIONS REGISTRY
// ==========================================================================
// docs/app.js: Issues #21 and #27 resolved.
const QUICKSTART_OS = {
    'win': `> [1] FLASH PREBUILT FIRMWARE TO AN ESP32-S3  (Recommended — no toolchain)
Grab your board's .bin set from the latest GitHub Release, then:
-----------------------------------------------------------------
# install esptool once:   pip install esptool
# variant = display | eth | wifi   (replace COM3 with your port)
esptool --chip esp32s3 -p COM3 -b 460800 write_flash 0x0 bootloader-esp32s3-display.bin 0x8000 partition-table-esp32s3-display.bin 0x20000 SipServer-esp32s3-display.bin

> [2] RUN ON A PC / RASPBERRY PI  (No ESP32 needed)
Paste this in Command Prompt or PowerShell:
-----------------------------------------------------------------
powershell -c "irm https://raw.githubusercontent.com/GlomarGadaffi/pocket-dial/main/install.ps1 | iex"

> [3] LOCAL DEVELOPMENT (if cloned):
-----------------------------------------------------------------
C:\\pocket-dial> quickstart.bat`,
    'nix': `> [1] FLASH PREBUILT FIRMWARE TO AN ESP32-S3  (Recommended — no toolchain)
Grab your board's .bin set from the latest GitHub Release, then:
-----------------------------------------------------------------
# install esptool once:   pip install esptool
# variant = display | eth | wifi   (replace /dev/ttyUSB0 with your port)
esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 write_flash 0x0 bootloader-esp32s3-display.bin 0x8000 partition-table-esp32s3-display.bin 0x20000 SipServer-esp32s3-display.bin

> [2] RUN ON A PC / RASPBERRY PI  (No ESP32 needed)
Paste this in your Linux / macOS Terminal (Bash):
-----------------------------------------------------------------
curl -fsSL https://raw.githubusercontent.com/GlomarGadaffi/pocket-dial/main/install.sh | sh

> [3] LOCAL DEVELOPMENT (if cloned):
-----------------------------------------------------------------
$ chmod +x quickstart.sh && ./quickstart.sh`
};

// ==========================================================================
// 3. ORACLE WORDS DEPOSITORY (TempleOS Inspired)
// ==========================================================================
const ORACLE_WORDS = [
    "God says the ethernet clock must be output on GPIO17.",
    "Accepting any credential prevents provisioning friction on trusted LANs.",
    "A 3KB stack is a pathway to load prohibited Xtensa reboots.",
    "We use double-line box drawings because standard borders lack soul.",
    "The W5500 SPI bus is pure, untainted by software handshakes.",
    "RTP flows peer-to-peer. The server remains a humble, stateless witness.",
    "Beware the dynamic_cast without standard guards; it brings memory ruin.",
    "A clean compile under MSVC and GCC is a covenant of peace.",
    "The 16-color CGA blue is the color of true code compilation.",
    "In flat trusted local networks, there are no passwords, only connections.",
    "A 500ms receive timeout delivers UdpServer from shutdown deadlocks."
];

// ==========================================================================
// 4. MAIN ENGINE EXECUTION CONTROL
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
    // Hardware Selector Initialisation
    initHardwareExplorer();

    // OS Tab Initialisation
    initQuickstartOSTabs();

    // Terminal Emulator System
    initTerminalEmulator();
});

// --- HARDWARE EXPLORER ---
function initHardwareExplorer() {
    const tabs = document.querySelectorAll(".board-tab");
    const container = document.getElementById("board-info-container");

    function renderBoard(key) {
        const board = HARDWARE_PROFILES[key];
        let specsHtml = "";
        for (const [sLabel, sVal] of Object.entries(board.specs)) {
            specsHtml += `
                <div class="board-spec-row">
                    <span class="spec-label">${sLabel}</span>
                    <span class="spec-val">${sVal}</span>
                </div>
            `;
        }

        container.innerHTML = `
            <div class="board-ascii-panel">
                <div class="board-title">&gt; PHYSICAL PINOUT DESIGNATOR</div>
                <pre class="ascii-frame">${board.ascii}</pre>
                <p class="block-text" style="font-size:13px; margin-top:5px; color:var(--text-secondary);">${board.desc}</p>
            </div>
            <div class="board-details-panel">
                <div class="board-title">&gt; SPECIFICATIONS</div>
                <div class="board-specs-table">
                    ${specsHtml}
                </div>
                <div class="config-code-block">
                    <div class="code-header">
                        <span>SPI_ETH_CONFIG.H</span>
                        <button class="copy-btn" onclick="copyCodeText(this)">COPY BLOCK</button>
                    </div>
                    <pre class="code-pre"><code>${board.code}</code></pre>
                </div>
            </div>
        `;
    }

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            renderBoard(tab.dataset.board);
        });
    });

    // Default Render
    renderBoard("t-eth-elite");
}

// Global copy helper
window.copyCodeText = function(btn) {
    const codeBlock = btn.closest(".config-code-block").querySelector(".code-pre code");
    navigator.clipboard.writeText(codeBlock.innerText).then(() => {
        const origText = btn.innerText;
        btn.innerText = "COPIED!";
        btn.style.borderColor = "var(--primary)";
        btn.style.color = "var(--primary)";
        setTimeout(() => {
            btn.innerText = origText;
            btn.style.borderColor = "";
            btn.style.color = "";
        }, 1500);
    });
};

// --- OS TABS EXPLORER ---
function initQuickstartOSTabs() {
    const tabs = document.querySelectorAll(".os-tab");
    const codeBox = document.getElementById("os-code-box");

    function renderOS(osKey) {
        codeBox.innerHTML = `
            <div class="config-code-block">
                <div class="code-header">
                    <span>${osKey === 'win' ? 'INSTALL — WINDOWS' : 'INSTALL — LINUX / macOS'}</span>
                    <button class="copy-btn" id="copy-os-btn">COPY SCRIPT</button>
                </div>
                <pre class="code-pre"><code id="os-code-content">${QUICKSTART_OS[osKey]}</code></pre>
            </div>
        `;

        document.getElementById("copy-os-btn").addEventListener("click", function() {
            const btn = this;
            const code = document.getElementById("os-code-content");
            navigator.clipboard.writeText(code.innerText).then(() => {
                btn.innerText = "COPIED!";
                btn.style.borderColor = "var(--primary)";
                btn.style.color = "var(--primary)";
                setTimeout(() => {
                    btn.innerText = "COPY SCRIPT";
                    btn.style.borderColor = "";
                    btn.style.color = "";
                }, 1500);
            });
        });
    }

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            renderOS(tab.dataset.os);
        });
    });

    renderOS("win");
}

// --- TERMINAL EMULATOR SHELL ---
function initTerminalEmulator() {
    const termInput = document.getElementById("terminal-input");
    const termOutput = document.getElementById("terminal-output");
    const termScreen = document.getElementById("terminal-screen");
    let isDialing = false;

    // Auto-focus terminal on body click if not selecting text
    termScreen.addEventListener("click", (e) => {
        if (e.target !== termInput) {
            termInput.focus();
        }
    });

    termInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const cmdRaw = termInput.value.trim();
            termInput.value = "";
            
            if (cmdRaw !== "") {
                handleCommand(cmdRaw);
            }
        }
    });

    // appendLine renders trusted, hardcoded markup. Any user-supplied or
    // externally-sourced text MUST be passed through escapeHtml() first.
    function appendLine(text, colorClass = "") {
        const line = document.createElement("div");
        line.className = colorClass;
        line.innerHTML = text;
        termOutput.appendChild(line);
        termScreen.scrollTop = termScreen.scrollHeight;
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function handleCommand(cmdLine) {
        appendLine(`<span class="prompt">guest@pocket-dial:&gt;</span> ${escapeHtml(cmdLine)}`, "highlight-white");

        if (isDialing) {
            if (cmdLine.toLowerCase() === "bye" || cmdLine.toLowerCase() === "cancel") {
                isDialing = false;
                appendLine("--> SENDING BYE Transaction...", "highlight-red");
                appendLine("<-- RECEIVING SIP/2.0 200 OK (Call Session Terminated)", "highlight-green");
                appendLine("[MEDIA SESSION CLOSED]");
            } else {
                appendLine("Call session active. Type <span class='highlight-red'>bye</span> to terminate.", "highlight-yellow");
            }
            return;
        }

        const parts = cmdLine.split(" ");
        const baseCmd = parts[0].toLowerCase();
        const arg = parts.slice(1).join(" ");

        switch (baseCmd) {
            case "help":
                appendLine("┌── AVAILABLE SIMULATED SHELL COMMANDS ────────────────┐", "highlight-cyan");
                appendLine("  help        — Show this technical help directory");
                appendLine("  registered  — Query registered local SIP endpoints");
                appendLine("  sessions    — List status of all active call sessions");
                appendLine("  dial &lt;ext&gt;  — Initiate mock SIP call flow simulation");
                appendLine("  uptime      — Display server system clock runtime statistics");
                appendLine("  oracle      — Query the TempleOS-style God Oracle text");
                appendLine("  ver         — Output target firmware version credentials");
                appendLine("  ascii       — Print physical phone ASCII graphic");
                appendLine("  clear       — Wipe the buffer logs clean");
                appendLine("└── Try typing: dial 102 ──────────────────────────────┘", "highlight-cyan");
                break;

            case "clear":
                termOutput.innerHTML = "";
                break;

            case "registered":
                appendLine("┌── SIP STATION REGISTRY DATABASE ───────────────────────┐", "highlight-green");
                appendLine("  Extension  IP Address       User-Agent       Status    ");
                appendLine("  ─────────────────────────────────────────────────────  ");
                appendLine("  101        192.168.1.51     Grandstream-2130 REGISTERED");
                appendLine("  102        192.168.1.52     MicroSIP-v3.21.3 REGISTERED");
                appendLine("  103        192.168.1.53     Linphone-Android REGISTERED");
                appendLine("  105        192.168.1.55     TelephoneOS-CGA  REGISTERED");
                appendLine("└────────────────────────────────────────────────────────┘", "highlight-green");
                break;

            case "sessions":
                appendLine("┌── ACTIVE SIP SESSION MAP ──────────────────────────────┐", "highlight-yellow");
                appendLine("  Call-ID          Caller   Callee   Status        Duration");
                appendLine("  ─────────────────────────────────────────────────────────");
                appendLine("  c8b417ad8a0112   101      103      ESTABLISHED   00:14:32");
                appendLine("└────────────────────────────────────────────────────────┘", "highlight-yellow");
                break;

            case "ver":
                appendLine("POCKET-DIAL Version: <span class='highlight-cyan'>v1.4.1</span>");
                appendLine("Hardened C++17 Core Engine (CMake Build: MSVC 19.x/GCC 11.x)");
                appendLine("lwIP Sockets binding: UDP/5060, HTTP/8080 (Web CGA Console)");
                break;

            case "uptime":
                const now = new Date();
                const hrs = String(now.getHours() % 12 + 1).padStart(2, "0");
                const mins = String(now.getMinutes()).padStart(2, "0");
                const secs = String(now.getSeconds()).padStart(2, "0");
                appendLine(`pocket-dial runtime: <span class='highlight-yellow'>00 days, ${hrs} hours, ${mins} minutes, ${secs} seconds</span>`);
                break;

            case "oracle":
                const rIdx = Math.floor(Math.random() * ORACLE_WORDS.length);
                appendLine(`God Oracle speaks: <span class='highlight-yellow'>"${ORACLE_WORDS[rIdx]}"</span>`);
                break;

            case "ascii":
                appendLine(
`     .---.
    /     \\
    \\_.._/
    |====|
    |    |   [SIP TELEPHONE UNIT]
    |====|   Model: pocket-dial CGA
    | () |   Auth: BYPASSED / TRUST
    |    |
    '----'`, "highlight-cyan");
                break;

            case "dial":
                if (!arg) {
                    appendLine("Error: Please specify target extension. Example: <span class='highlight-cyan'>dial 102</span>", "highlight-red");
                    break;
                }
                simulateSipCall(arg);
                break;

            default:
                appendLine(`Bad command or extension: "${escapeHtml(baseCmd)}". Type <span class='highlight-cyan'>help</span> for valid commands.`, "highlight-red");
        }
    }

    // Interactive SIP Call flow animator
    function simulateSipCall(ext) {
        isDialing = true;
        appendLine(`--> INITIATING SIP CALL FLOW FOR EXTENSION [${escapeHtml(ext)}]`, "highlight-cyan");
        
        setTimeout(() => {
            if (!isDialing) return;
            appendLine("--> SENDING:   INVITE sip:" + escapeHtml(ext) + "@192.168.1.1:5060 SIP/2.0", "highlight-white");
        }, 600);

        setTimeout(() => {
            if (!isDialing) return;
            appendLine("<-- RECEIVING: SIP/2.0 100 Trying", "highlight-green");
        }, 1200);

        setTimeout(() => {
            if (!isDialing) return;
            appendLine("<-- RECEIVING: SIP/2.0 180 Ringing (Endpoint is alerting)", "highlight-green");
        }, 1800);

        setTimeout(() => {
            if (!isDialing) return;
            appendLine("<-- RECEIVING: SIP/2.0 200 OK (Call Accepted)", "highlight-green");
            appendLine("--> SENDING:   ACK sip:" + escapeHtml(ext) + "@192.168.1.1:5060 SIP/2.0", "highlight-white");
        }, 3000);

        setTimeout(() => {
            if (!isDialing) return;
            appendLine("==========================================================", "highlight-yellow");
            appendLine("[MEDIA SESSION ESTABLISHED: RTP Stream flowing peer-to-peer]", "highlight-yellow");
            appendLine("==========================================================", "highlight-yellow");
            appendLine("Simulated call active! Type <span class='highlight-red'>bye</span> to hang up.", "highlight-cyan");
        }, 3600);
    }
}
