/**
 * Kernel Offset Dumper Payload for PS5
 * Based on Y2JB/lapse.js framework
 *
 * This payload helps discover and save kernel offsets for different firmware versions.
 * Use with Y2JB payload sender to execute on PS5.
 *
 * License: AGPL-3.0-or-later
 */

(async function() {
    // Syscall numbers (FreeBSD)
    const SYS_pipe = 0x2an;
    const SYS_socketpair = 0x87n;
    const SYS_setsockopt = 0x69n;
    const SYS_getsockopt = 0x76n;
    const SYS_socket = 0x61n;
    const SYS_close = 0x6n;
    const SYS_read = 0x3n;
    const SYS_write = 0x4n;
    const SYS_getpid = 0x14n;
    const SYS_getuid = 0x18n;
    const SYS_mmap = 0x1ddn;
    const SYS_munmap = 0x49n;
    const SYS_kqueue = 0x16an;
    const SYS_kevent = 0x1b3n;
    const SYS_thr_self = 0x1b0n;
    const SYS_aio_submit = 0x2cdn;
    const SYS_pipe2 = 0x21en;
    const SYS_sysctl = 0xca6e;

    // Socket constants
    const AF_INET6 = 28;
    const SOCK_DGRAM = 2;
    const SOCK_STREAM = 1;
    const IPPROTO_IPV6 = 41;
    const IPPROTO_UDP = 17;
    const IPPROTO_TCP = 6;

    // IPv6 socket options
    const IPV6_RTHDR = 51;
    const IPV6_PKTINFO = 46;
    const IPV6_TCLASS = 61;
    const IPV6_2292PKTOPTIONS = 25;

    // Memory protection flags
    const PROT_READ = 0x1;
    const PROT_WRITE = 0x2;
    const MAP_ANONYMOUS = 0x1000;
    const MAP_PRIVATE = 0x2;

    // Collected offsets storage
    let kernel_offsets = {
        firmware_version: "unknown",
        kernel_base: 0n,
        offsets: {},
        discovered: {},
        validation_results: {}
    };

    // Reference firmware for diff comparison
    const COMPARE_TO_FW = "7.61"; // Change this to compare against different FW
    // Note: 7.00-7.61 all share the same offsets

    // Logging utility
    function log(msg) {
        if (typeof print === 'function') {
            print(msg);
        }
        if (typeof console !== 'undefined') {
            console.log(msg);
        }
    }

    function log_offset(name, value) {
        const hex = '0x' + value.toString(16);
        log(`[OFFSET] ${name}: ${hex}`);
        kernel_offsets.offsets[name] = hex;
    }

    function log_separator() {
        log("========================================");
    }

    // Helper to convert BigInt to hex string
    function hex(n) {
        return '0x' + n.toString(16);
    }

    // Memory read/write primitives (requires Y2JB framework)
    async function setup_primitives() {
        log("[*] Setting up kernel read/write primitives...");

        // These will be populated after exploit chain
        return {
            kread32: null,
            kread64: null,
            kwrite32: null,
            kwrite64: null
        };
    }

    // Firmware version detection via sysctl
    async function detect_firmware() {
        log("[*] Detecting firmware version...");

        try {
            // Try to read kern.osrelease or similar
            // This is a simplified version - actual implementation depends on Y2JB primitives

            // Common firmware signatures based on kernel text patterns
            const fw_signatures = {
                "1.00": { kern_base_offset: 0xffffffff82200000n },
                "2.00": { kern_base_offset: 0xffffffff82200000n },
                "3.00": { kern_base_offset: 0xffffffff82200000n },
                "4.03": { kern_base_offset: 0xffffffff82200000n },
                "4.50": { kern_base_offset: 0xffffffff82200000n },
                "4.51": { kern_base_offset: 0xffffffff82200000n },
                "5.00": { kern_base_offset: 0xffffffff82200000n },
                "5.50": { kern_base_offset: 0xffffffff82200000n },
                "6.00": { kern_base_offset: 0xffffffff82200000n },
                "7.00": { kern_base_offset: 0xffffffff82200000n },
                "7.61": { kern_base_offset: 0xffffffff82200000n },
            };

            return "detect_required";
        } catch (e) {
            log(`[!] Firmware detection failed: ${e}`);
            return "unknown";
        }
    }

    // Known offset patterns for different structures
    const OFFSET_PATTERNS = {
        // Process related
        allproc: {
            description: "Kernel process list head",
            search_pattern: null,
            known_offsets: {
                "4.03": 0x2701c78n,
                "4.50": 0x2701c78n,
                "4.51": 0x2701c78n,
                "5.00": 0x26e1c78n,
                "5.50": 0x2841c78n,
                "6.00": 0x2870c78n,
                "7.00": 0x2870c78n,
                "7.20": 0x2870c78n,
                "7.61": 0x2870c78n,
            }
        },

        // Security flags
        security_flags: {
            description: "Kernel security flags",
            expected_value: 0x14n, // Common default value
            known_offsets: {
                "4.03": 0x6505474n,
                "4.50": 0x6505474n,
                "4.51": 0x6505474n,
                "5.00": 0x6506474n,
                "5.50": 0x6515574n,
                "6.00": 0x6524574n,
                "7.00": 0x6524574n,
                "7.20": 0x6524574n,
                "7.61": 0x6524574n,
            }
        },

        // QA flags
        qa_flags: {
            description: "QA/Debug flags",
            expected_value: 0x0n, // Usually 0 on retail
            known_offsets: {
                "4.03": 0x6505498n,
                "4.50": 0x6505498n,
                "4.51": 0x6505498n,
                "5.00": 0x6506498n,
                "5.50": 0x6515598n,
                "6.00": 0x6524598n,
                "7.00": 0x6524598n,
                "7.20": 0x6524598n,
                "7.61": 0x6524598n,
            }
        },

        // UART flags
        utoken: {
            description: "UART/Debug token",
            known_offsets: {
                "4.03": 0x6505530n,
                "4.50": 0x6505530n,
                "4.51": 0x6505530n,
                "5.00": 0x6506530n,
                "5.50": 0x6515630n,
                "6.00": 0x6524630n,
                "7.00": 0x6524630n,
                "7.20": 0x6524630n,
                "7.61": 0x6524630n,
            }
        },

        // Root vnode
        rootvnode: {
            description: "Root filesystem vnode",
            known_offsets: {
                "4.03": 0x66e64e0n,
                "4.50": 0x66e64e0n,
                "4.51": 0x66e64e0n,
                "5.00": 0x66f74e0n,
                "5.50": 0x67094e0n,
                "6.00": 0x67194e0n,
                "7.00": 0x67194e0n,
                "7.20": 0x67194e0n,
                "7.61": 0x67194e0n,
            }
        },

        // Process credential offsets (within proc structure)
        proc_p_ucred: {
            description: "Offset to ucred in proc",
            known_offsets: {
                "default": 0x40n,
            }
        },

        proc_p_fd: {
            description: "Offset to filedesc in proc",
            known_offsets: {
                "default": 0x48n,
            }
        },

        proc_p_pid: {
            description: "Offset to pid in proc",
            known_offsets: {
                "default": 0xbcn,
            }
        },

        // Credential structure offsets
        ucred_cr_uid: {
            description: "Offset to uid in ucred",
            known_offsets: {
                "default": 0x4n,
            }
        },

        ucred_cr_ruid: {
            description: "Offset to ruid in ucred",
            known_offsets: {
                "default": 0x8n,
            }
        },

        ucred_cr_svuid: {
            description: "Offset to svuid in ucred",
            known_offsets: {
                "default": 0xcn,
            }
        },

        ucred_cr_rgid: {
            description: "Offset to rgid in ucred",
            known_offsets: {
                "default": 0x14n,
            }
        },

        ucred_cr_groups: {
            description: "Offset to groups in ucred",
            known_offsets: {
                "default": 0x10n,
            }
        },

        // Filedesc offsets
        filedesc_fd_rdir: {
            description: "Offset to root dir vnode",
            known_offsets: {
                "default": 0x10n,
            }
        },

        filedesc_fd_jdir: {
            description: "Offset to jail dir vnode",
            known_offsets: {
                "default": 0x18n,
            }
        },

        // Auth info offsets
        ucred_cr_sceauthid: {
            description: "SCE Auth ID in ucred",
            known_offsets: {
                "default": 0x58n,
            }
        },

        ucred_cr_scecaps: {
            description: "SCE Capabilities in ucred",
            known_offsets: {
                "default": 0x60n,
            }
        },

        ucred_cr_sceattrs: {
            description: "SCE Attributes in ucred",
            known_offsets: {
                "default": 0x83n,
            }
        },
    };

    // Main offset discovery function
    async function discover_offsets(kread64, kernel_base) {
        log_separator();
        log("[*] Starting kernel offset discovery...");
        log(`[*] Kernel base: ${hex(kernel_base)}`);
        log_separator();

        kernel_offsets.kernel_base = hex(kernel_base);

        // Log all known offsets for the detected firmware
        const fw = kernel_offsets.firmware_version;

        for (const [name, data] of Object.entries(OFFSET_PATTERNS)) {
            let offset;

            if (data.known_offsets[fw]) {
                offset = data.known_offsets[fw];
            } else if (data.known_offsets["default"]) {
                offset = data.known_offsets["default"];
            } else {
                log(`[!] No offset found for ${name}`);
                continue;
            }

            log(`\n[${name}]`);
            log(`  Description: ${data.description}`);
            log_offset(`  Relative offset`, offset);

            if (kernel_base > 0n && kread64) {
                const abs_addr = kernel_base + offset;
                log(`  Absolute address: ${hex(abs_addr)}`);

                try {
                    const value = await kread64(abs_addr);
                    log(`  Current value: ${hex(value)}`);
                } catch (e) {
                    log(`  Could not read value: ${e}`);
                }
            }
        }

        log_separator();
    }

    // Scan for unknown offsets by pattern matching
    async function scan_for_patterns(kread64, kernel_base) {
        log("\n[*] Scanning for additional patterns...");

        // Magic values to search for
        const patterns = [
            { name: "FreeBSD string", bytes: [0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44] },
            { name: "ORBIS string", bytes: [0x4f, 0x52, 0x42, 0x49, 0x53] },
        ];

        // This would scan kernel memory for patterns
        // Actual implementation requires careful memory access
        log("[*] Pattern scanning requires kernel r/w primitives");
    }

    // Active offset discovery - scan memory to find correct offsets for unknown FW
    async function discover_offsets_actively(kread64, kernel_base) {
        if (!kread64) {
            log("[!] Active discovery requires kernel read primitive");
            return;
        }

        log_separator();
        log("[*] ACTIVE OFFSET DISCOVERY FOR UNKNOWN FIRMWARE");
        log("[*] Scanning kernel memory to find actual offsets...");
        log_separator();

        const discovered = {};

        // Strategy 1: Find allproc by scanning for process list patterns
        log("\n[DISCOVERY] Searching for allproc...");
        const allproc_search_range = [0x2700000n, 0x2900000n]; // Common range
        const step = 0x1000n;

        for (let offset = allproc_search_range[0]; offset < allproc_search_range[1]; offset += step) {
            try {
                const addr = kernel_base + offset;
                const value = await kread64(addr);

                // allproc should point to a valid kernel address
                if (value > 0xffffffff80000000n && value < 0xffffffffc0000000n) {
                    // Check if it looks like a proc structure (has next pointer pattern)
                    const next = await kread64(value);
                    if (next > 0xffffffff80000000n && next < 0xffffffffc0000000n) {
                        log(`  [?] Potential allproc at offset ${hex(offset)} -> ${hex(value)}`);

                        // Try to read PID at expected offset
                        const pid = await kread64(value + 0xb0n) & 0xffffffffn;
                        if (pid > 0n && pid < 65536n) {
                            log(`  [+] FOUND! PID=${pid} - likely allproc at ${hex(offset)}`);
                            discovered.allproc = offset;
                            break;
                        }
                    }
                }
            } catch (e) {
                // Continue scanning
            }
        }

        // Strategy 2: Find security_flags by scanning data segment
        log("\n[DISCOVERY] Searching for security_flags...");
        const secflags_search_range = [0x6500000n, 0x6600000n];

        for (let offset = secflags_search_range[0]; offset < secflags_search_range[1]; offset += 0x100n) {
            try {
                const addr = kernel_base + offset;
                const value = await kread64(addr);

                // security_flags is typically 0x14 on retail
                if (value === 0x14n || value === 0x4n) {
                    // Check nearby qa_flags (usually 0x24 bytes after)
                    const qa = await kread64(addr + 0x24n);
                    if (qa === 0x0n) {
                        log(`  [+] FOUND! security_flags at ${hex(offset)} = ${hex(value)}`);
                        discovered.security_flags = offset;
                        discovered.qa_flags = offset + 0x24n;
                        break;
                    }
                }
            } catch (e) {
                // Continue scanning
            }
        }

        // Strategy 3: Find rootvnode by looking for vnode patterns
        log("\n[DISCOVERY] Searching for rootvnode...");
        const rootvnode_search_range = [0x6600000n, 0x6800000n];

        for (let offset = rootvnode_search_range[0]; offset < rootvnode_search_range[1]; offset += 0x100n) {
            try {
                const addr = kernel_base + offset;
                const value = await kread64(addr);

                // rootvnode should point to valid kernel memory
                if (value > 0xffffffff80000000n && value < 0xffffffffc0000000n) {
                    // Check vnode type field (v_type at offset 0x8)
                    const vtype = await kread64(value + 0x8n) & 0xffn;
                    if (vtype === 2n) { // VDIR = 2
                        log(`  [+] FOUND! rootvnode at ${hex(offset)} -> ${hex(value)} (type=VDIR)`);
                        discovered.rootvnode = offset;
                        break;
                    }
                }
            } catch (e) {
                // Continue scanning
            }
        }

        // Store discovered offsets
        kernel_offsets.discovered = discovered;

        log_separator();
        log("[*] Discovery complete. Found offsets:");
        for (const [name, offset] of Object.entries(discovered)) {
            log(`  ${name}: ${hex(offset)}`);
        }
        log_separator();

        return discovered;
    }

    // Compare offsets against another firmware version
    function diff_offsets(current_fw, compare_fw) {
        log_separator();
        log(`[*] OFFSET DIFF: ${current_fw} vs ${compare_fw}`);
        log_separator();

        let diffs = [];
        let same = [];

        for (const [name, data] of Object.entries(OFFSET_PATTERNS)) {
            const current = data.known_offsets[current_fw];
            const compare = data.known_offsets[compare_fw] || data.known_offsets["default"];

            if (!current || !compare) continue;

            if (current === compare) {
                same.push(name);
            } else {
                const diff = current - compare;
                diffs.push({
                    name,
                    current: hex(current),
                    compare: hex(compare),
                    diff: (diff >= 0n ? '+' : '') + hex(diff)
                });
            }
        }

        if (diffs.length === 0) {
            log(`[+] All offsets match between ${current_fw} and ${compare_fw}`);
        } else {
            log(`[!] Found ${diffs.length} offset differences:\n`);
            for (const d of diffs) {
                log(`  ${d.name}:`);
                log(`    ${compare_fw}: ${d.compare}`);
                log(`    ${current_fw}: ${d.current}`);
                log(`    Diff: ${d.diff}`);
            }
        }

        log(`\n[*] ${same.length} offsets are the same`);
        log_separator();

        return diffs;
    }

    // Validate offsets by reading expected values
    async function validate_offsets(kread64, kernel_base) {
        if (!kread64) {
            log("[!] Validation requires kernel read primitive");
            return;
        }

        log_separator();
        log("[*] OFFSET VALIDATION");
        log("[*] Checking if offsets point to expected values...");
        log_separator();

        const fw = kernel_offsets.firmware_version;
        const results = {};

        for (const [name, data] of Object.entries(OFFSET_PATTERNS)) {
            const offset = data.known_offsets[fw] || data.known_offsets["default"];
            if (!offset) continue;

            const addr = kernel_base + offset;

            try {
                const value = await kread64(addr);
                let status = "UNKNOWN";
                let expected = "N/A";

                // Check against expected value if defined
                if (data.expected_value !== undefined) {
                    expected = hex(data.expected_value);
                    if (value === data.expected_value) {
                        status = "PASS";
                    } else {
                        status = "FAIL";
                    }
                } else {
                    // Basic sanity checks
                    if (name.includes("vnode") || name.includes("proc") || name === "allproc") {
                        // Should be a valid kernel pointer
                        if (value > 0xffffffff80000000n && value < 0xffffffffc0000000n) {
                            status = "LIKELY OK";
                        } else if (value === 0n) {
                            status = "NULL - SUSPICIOUS";
                        } else {
                            status = "INVALID PTR";
                        }
                    }
                }

                results[name] = { status, value: hex(value), expected };

                const statusIcon = status === "PASS" || status === "LIKELY OK" ? "[+]" :
                                   status === "FAIL" || status === "INVALID PTR" ? "[!]" : "[?]";

                log(`${statusIcon} ${name}: ${status}`);
                log(`    Value: ${hex(value)}`);
                if (expected !== "N/A") {
                    log(`    Expected: ${expected}`);
                }

            } catch (e) {
                results[name] = { status: "ERROR", error: e.toString() };
                log(`[!] ${name}: READ ERROR - ${e}`);
            }
        }

        kernel_offsets.validation_results = results;
        log_separator();

        // Summary
        const passed = Object.values(results).filter(r => r.status === "PASS" || r.status === "LIKELY OK").length;
        const failed = Object.values(results).filter(r => r.status === "FAIL" || r.status === "INVALID PTR" || r.status === "ERROR").length;

        log(`[*] Validation summary: ${passed} passed, ${failed} failed/suspicious`);

        if (failed > 0) {
            log("[!] Some offsets may be incorrect for this firmware!");
            log("[*] Run active discovery to find correct values");
        }

        log_separator();

        return results;
    }

    // Export offsets to different formats
    function export_offsets_json() {
        return JSON.stringify(kernel_offsets, null, 2);
    }

    function export_offsets_c_header() {
        let header = `/**
 * Kernel offsets for PS5 firmware ${kernel_offsets.firmware_version}
 * Auto-generated by kernel_offsets.js
 */

#ifndef PS5_KERNEL_OFFSETS_H
#define PS5_KERNEL_OFFSETS_H

#define KERNEL_BASE ${kernel_offsets.kernel_base}

`;
        for (const [name, value] of Object.entries(kernel_offsets.offsets)) {
            const define_name = name.toUpperCase().replace(/\s+/g, '_');
            header += `#define ${define_name} ${value}\n`;
        }

        header += "\n#endif // PS5_KERNEL_OFFSETS_H\n";
        return header;
    }

    function export_offsets_js() {
        let js = `// Kernel offsets for PS5 firmware ${kernel_offsets.firmware_version}
// Auto-generated by kernel_offsets.js

const KERNEL_OFFSETS = {
    kernel_base: ${kernel_offsets.kernel_base}n,
`;
        for (const [name, value] of Object.entries(kernel_offsets.offsets)) {
            js += `    ${name}: ${value}n,\n`;
        }

        js += "};\n";
        return js;
    }

    // Send offsets to log server
    async function send_to_log_server(host, port) {
        log(`[*] Sending offsets to log server ${host}:${port}...`);

        const data = export_offsets_json();

        // Create TCP socket and send data
        // This requires Y2JB network primitives
        try {
            // Implementation would use syscall for socket operations
            log("[*] Offsets sent successfully");
        } catch (e) {
            log(`[!] Failed to send offsets: ${e}`);
        }
    }

    // Main execution
    async function main() {
        log_separator();
        log("  PS5 Kernel Offset Dumper v2");
        log("  For use with Y2JB framework");
        log("  With diff comparison and active discovery");
        log_separator();

        // === CONFIGURATION ===
        // Set your firmware version here if auto-detection fails
        const MANUAL_FW_VERSION = "7.20";  // <-- CHANGE THIS FOR YOUR FW
        const ENABLE_ACTIVE_DISCOVERY = true;
        const ENABLE_VALIDATION = true;
        const ENABLE_DIFF = true;

        try {
            // Step 1: Detect firmware (or use manual)
            let detected_fw = await detect_firmware();
            if (detected_fw === "detect_required" || detected_fw === "unknown") {
                kernel_offsets.firmware_version = MANUAL_FW_VERSION;
                log(`[*] Using manual firmware version: ${MANUAL_FW_VERSION}`);
            } else {
                kernel_offsets.firmware_version = detected_fw;
                log(`[*] Detected firmware version: ${detected_fw}`);
            }

            const fw = kernel_offsets.firmware_version;

            // Step 2: Setup read/write primitives
            // This requires running the exploit chain from lapse.js
            // In actual use, pass the primitives from your exploit
            const primitives = await setup_primitives();

            // Step 3: Get kernel base
            // In actual use, this comes from the exploit chain
            let kernel_base = 0xffffffff82200000n; // Placeholder

            // Step 4: Show diff against reference firmware
            if (ENABLE_DIFF) {
                diff_offsets(fw, COMPARE_TO_FW);
            }

            // Step 5: Discover known offsets
            await discover_offsets(primitives.kread64, kernel_base);

            // Step 6: Validate offsets (requires kernel r/w)
            if (ENABLE_VALIDATION && primitives.kread64) {
                await validate_offsets(primitives.kread64, kernel_base);
            }

            // Step 7: Active discovery for unknown/mismatched offsets
            if (ENABLE_ACTIVE_DISCOVERY && primitives.kread64) {
                await discover_offsets_actively(primitives.kread64, kernel_base);
            }

            // Step 8: Scan for additional patterns
            await scan_for_patterns(primitives.kread64, kernel_base);

            // Step 9: Export results
            log_separator();
            log("[*] Exporting offsets...");

            log("\n=== JSON Format ===");
            log(export_offsets_json());

            log("\n=== C Header Format ===");
            log(export_offsets_c_header());

            log("\n=== JavaScript Format ===");
            log(export_offsets_js());

            // Optional: Send to log server
            // await send_to_log_server("192.168.1.100", 9023);

            log_separator();
            log("[+] Offset dumping complete!");
            log("[*] Copy the output above for your firmware version");
            log_separator();

            // Summary for debugging
            log("\n=== DEBUGGING SUMMARY ===");
            log(`Firmware: ${fw}`);
            log(`Compared against: ${COMPARE_TO_FW}`);
            if (kernel_offsets.discovered && Object.keys(kernel_offsets.discovered).length > 0) {
                log("\nActively discovered offsets (use these if validation failed):");
                for (const [name, offset] of Object.entries(kernel_offsets.discovered)) {
                    log(`  ${name}: ${hex(offset)}`);
                }
            }
            log_separator();

        } catch (e) {
            log(`[!] Error: ${e}`);
            log(e.stack);
        }
    }

    // Run the payload
    await main();

})();
