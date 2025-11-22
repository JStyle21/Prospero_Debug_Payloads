/**
 * Kernel Offset Dumper Payload for PS5
 * Based on Y2JB framework
 *
 * Auto-detects firmware and dumps kernel offsets to log server.
 * Run log_server.py on your PC first!
 *
 * License: AGPL-3.0-or-later
 */

(async function() {
    // ============================================
    // LOG SERVER CONFIG - CHANGE THIS
    // ============================================
    const LOG_SERVER_IP = "192.168.1.100";  // Your PC's IP
    const LOG_SERVER_PORT = 9023;            // Default Y2JB log port
    // ============================================

    // Buffer to collect all output
    let logBuffer = [];

    function log(msg) {
        logBuffer.push(msg);
        if (typeof print === 'function') print(msg);
        if (typeof console !== 'undefined') console.log(msg);
    }

    // Send logs to server via fetch (HTTP POST)
    async function sendToLogServer() {
        const output = logBuffer.join('\n');

        try {
            // Method 1: Try fetch (works in modern WebKit)
            if (typeof fetch !== 'undefined') {
                await fetch(`http://${LOG_SERVER_IP}:${LOG_SERVER_PORT}/log`, {
                    method: 'POST',
                    body: output,
                    headers: { 'Content-Type': 'text/plain' }
                });
                return true;
            }

            // Method 2: Try XMLHttpRequest
            if (typeof XMLHttpRequest !== 'undefined') {
                return new Promise((resolve) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', `http://${LOG_SERVER_IP}:${LOG_SERVER_PORT}/log`, true);
                    xhr.setRequestHeader('Content-Type', 'text/plain');
                    xhr.onload = () => resolve(true);
                    xhr.onerror = () => resolve(false);
                    xhr.send(output);
                });
            }
        } catch (e) {
            // Silently fail - output is still in console
        }
        return false;
    }

    function hex(n) {
        return '0x' + n.toString(16);
    }

    // Auto-detect firmware version at runtime
    function detect_firmware() {
        let fw = "unknown";

        // Method 1: Check if Y2JB provides firmware info
        if (typeof window !== 'undefined' && window.firmware) {
            fw = window.firmware;
        }
        // Method 2: Check navigator userAgent for WebKit version hints
        else if (typeof navigator !== 'undefined' && navigator.userAgent) {
            const ua = navigator.userAgent;
            // PS5 WebKit versions map to firmware
            if (ua.includes('PlayStation 5')) {
                // Extract version hints from userAgent
                if (ua.includes('WebKit/605')) fw = "4.03";
                else if (ua.includes('WebKit/610')) fw = "5.00";
                else if (ua.includes('WebKit/615')) fw = "6.00";
                else if (ua.includes('WebKit/618')) fw = "7.00";
            }
        }
        // Method 3: Check global fw variable (set by some exploits)
        else if (typeof fw_version !== 'undefined') {
            fw = fw_version;
        }
        // Method 4: Check for common Y2JB globals
        else if (typeof config !== 'undefined' && config.firmware) {
            fw = config.firmware;
        }

        return fw;
    }

    // Get current date/time
    function get_timestamp() {
        const now = new Date();
        return now.toISOString();
    }

    // All known kernel offsets by firmware version
    const OFFSETS = {
        // Kernel data segment offsets
        allproc: {
            "4.03": 0x2701c78n, "4.50": 0x2701c78n, "4.51": 0x2701c78n,
            "5.00": 0x26e1c78n, "5.50": 0x2841c78n,
            "6.00": 0x2870c78n,
            "7.00": 0x2870c78n, "7.20": 0x2870c78n, "7.61": 0x2870c78n,
        },
        security_flags: {
            "4.03": 0x6505474n, "4.50": 0x6505474n, "4.51": 0x6505474n,
            "5.00": 0x6506474n, "5.50": 0x6515574n,
            "6.00": 0x6524574n,
            "7.00": 0x6524574n, "7.20": 0x6524574n, "7.61": 0x6524574n,
        },
        qa_flags: {
            "4.03": 0x6505498n, "4.50": 0x6505498n, "4.51": 0x6505498n,
            "5.00": 0x6506498n, "5.50": 0x6515598n,
            "6.00": 0x6524598n,
            "7.00": 0x6524598n, "7.20": 0x6524598n, "7.61": 0x6524598n,
        },
        utoken: {
            "4.03": 0x6505530n, "4.50": 0x6505530n, "4.51": 0x6505530n,
            "5.00": 0x6506530n, "5.50": 0x6515630n,
            "6.00": 0x6524630n,
            "7.00": 0x6524630n, "7.20": 0x6524630n, "7.61": 0x6524630n,
        },
        rootvnode: {
            "4.03": 0x66e64e0n, "4.50": 0x66e64e0n, "4.51": 0x66e64e0n,
            "5.00": 0x66f74e0n, "5.50": 0x67094e0n,
            "6.00": 0x67194e0n,
            "7.00": 0x67194e0n, "7.20": 0x67194e0n, "7.61": 0x67194e0n,
        },
    };

    // Structure field offsets (same across all firmwares)
    const STRUCT_OFFSETS = {
        // proc structure
        proc_p_ucred: 0x40n,
        proc_p_fd: 0x48n,
        proc_p_pid: 0xbcn,

        // ucred structure
        ucred_cr_uid: 0x4n,
        ucred_cr_ruid: 0x8n,
        ucred_cr_svuid: 0xcn,
        ucred_cr_rgid: 0x14n,
        ucred_cr_groups: 0x10n,
        ucred_cr_sceauthid: 0x58n,
        ucred_cr_scecaps: 0x60n,
        ucred_cr_sceattrs: 0x83n,

        // filedesc structure
        filedesc_fd_rdir: 0x10n,
        filedesc_fd_jdir: 0x18n,
    };

    // Main
    const FIRMWARE_VERSION = detect_firmware();
    const timestamp = get_timestamp();

    log("========================================");
    log("  PS5 Kernel Offset Dumper");
    log("========================================");
    log("");

    // Dump runtime environment info
    log("=== RUNTIME INFO ===");
    log("");
    log(`Timestamp: ${timestamp}`);
    log(`Detected FW: ${FIRMWARE_VERSION}`);

    if (typeof navigator !== 'undefined') {
        log(`UserAgent: ${navigator.userAgent}`);
        log(`Platform: ${navigator.platform || 'N/A'}`);
        log(`Language: ${navigator.language || 'N/A'}`);
    }

    if (typeof window !== 'undefined') {
        log(`Screen: ${window.screen?.width || '?'}x${window.screen?.height || '?'}`);
        if (window.firmware) log(`window.firmware: ${window.firmware}`);
    }

    if (typeof fw_version !== 'undefined') {
        log(`fw_version global: ${fw_version}`);
    }

    log("");

    // Check if firmware is supported
    const testOffset = OFFSETS.allproc[FIRMWARE_VERSION];
    if (!testOffset) {
        log(`[!] WARNING: Firmware "${FIRMWARE_VERSION}" not in offset table!`);
        log("[*] Supported: 4.03, 4.50, 4.51, 5.00, 5.50, 6.00, 7.00, 7.20, 7.61");
        log("[*] Will show all available offsets below");
        log("[*] Add your firmware offsets to the OFFSETS table");
        log("");

        // Show all available firmwares
        log("=== ALL AVAILABLE OFFSETS ===");
        log("");
        for (const [name, versions] of Object.entries(OFFSETS)) {
            log(`${name}:`);
            for (const [fw, offset] of Object.entries(versions)) {
                log(`  ${fw}: ${hex(offset)}`);
            }
        }
        return;
    }

    // Print kernel data offsets
    log("=== KERNEL DATA OFFSETS ===");
    log("");
    for (const [name, versions] of Object.entries(OFFSETS)) {
        const offset = versions[FIRMWARE_VERSION];
        if (offset) {
            log(`${name}: ${hex(offset)}`);
        }
    }

    // Print structure offsets
    log("");
    log("=== STRUCTURE FIELD OFFSETS ===");
    log("");
    for (const [name, offset] of Object.entries(STRUCT_OFFSETS)) {
        log(`${name}: ${hex(offset)}`);
    }

    // Print as copy-paste JavaScript format
    log("");
    log("=== COPY-PASTE FORMAT ===");
    log("");
    log(`// Offsets for firmware ${FIRMWARE_VERSION}`);
    log("const offsets = {");
    for (const [name, versions] of Object.entries(OFFSETS)) {
        const offset = versions[FIRMWARE_VERSION];
        if (offset) {
            log(`    ${name}: ${hex(offset)}n,`);
        }
    }
    log("};");

    log("");
    log("========================================");
    log("[+] Done!");
    log("========================================");

    // Send all output to log server
    log("");
    log(`[*] Sending to ${LOG_SERVER_IP}:${LOG_SERVER_PORT}...`);

    const sent = await sendToLogServer();
    if (sent) {
        log("[+] Sent to log server successfully!");
    } else {
        log("[!] Could not send to log server");
        log("[*] Check LOG_SERVER_IP and run log_server.py");
    }

})();
