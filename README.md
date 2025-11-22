# Prospero Debug Payloads

Debug and utility payloads for PS5 (Prospero) kernel research, designed for use with the [Y2JB](https://github.com/Gezine/Y2JB) framework.

## Payloads

### kernel_offsets.js

A utility payload that discovers, prints, and exports kernel offsets for your PS5 firmware version.

**Features:**
- Detects firmware version
- Dumps known kernel offsets (allproc, security_flags, qa_flags, rootvnode, etc.)
- Exports offsets in multiple formats (JSON, C header, JavaScript)
- Includes structure field offsets (proc, ucred, filedesc)
- **Diff comparison** - compare offsets between firmware versions
- **Validation** - verify offsets point to expected values
- **Active discovery** - scan kernel memory to find correct offsets for unknown FW

**Usage:**
```bash
# Send payload to PS5 using Y2JB payload_sender
python payload_sender.py kernel_offsets.js
```

## Supported Firmware Versions

The payloads include known offsets for:
- 4.03, 4.50, 4.51
- 5.00, 5.50
- 6.00
- 7.00, 7.20, 7.61 (all use same offsets)

## Requirements

- PS5 with compatible firmware
- Y2JB framework setup
- Network connection between PS5 and host PC

## Disclaimer

These payloads are provided for educational and research purposes only. Use responsibly and only on devices you own.

## License

AGPL-3.0-or-later

## Credits

Based on the Y2JB framework and lapse.js exploit chain by Gezine.
