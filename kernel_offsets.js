/**
 * Kernel Offset Dumper Payload for PS5
 * Based on Y2JB framework
 *
 * Simply prints all known kernel offsets for your firmware version.
 * Easy to share - just change FIRMWARE_VERSION for your console.
 *
 * License: AGPL-3.0-or-later
 */

(async function() {
    // ============================================
    // CONFIGURATION - CHANGE THIS FOR YOUR FW
    // ============================================
    const FIRMWARE_VERSION = "7.20";
    // ============================================

    function log(msg) {
        if (typeof print === 'function') print(msg);
        if (typeof console !== 'undefined') console.log(msg);
    }

    function hex(n) {
        return '0x' + n.toString(16);
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
    log("========================================");
    log("  PS5 Kernel Offset Dumper");
    log(`  Firmware: ${FIRMWARE_VERSION}`);
    log("========================================");
    log("");

    // Check if firmware is supported
    const testOffset = OFFSETS.allproc[FIRMWARE_VERSION];
    if (!testOffset) {
        log(`[!] ERROR: Firmware ${FIRMWARE_VERSION} not found!`);
        log("[*] Supported: 4.03, 4.50, 4.51, 5.00, 5.50, 6.00, 7.00, 7.20, 7.61");
        log("[*] Add your firmware offsets to the OFFSETS table above");
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
    log("[+] Done! Copy the offsets above.");
    log("========================================");

})();
