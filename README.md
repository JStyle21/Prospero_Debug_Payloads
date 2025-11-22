# Prospero Debug Payloads

Debug and utility payloads for PS5 (Prospero) kernel research, designed for use with the [Y2JB](https://github.com/Gezine/Y2JB) framework.

## Payloads

### kernel_offsets.js

A utility payload that discovers, prints, and exports kernel offsets for your PS5 firmware version.

**Features:**
- Auto-detects firmware version at runtime
- Dumps runtime info (userAgent, platform, screen, etc.)
- Dumps known kernel offsets (allproc, security_flags, qa_flags, rootvnode, etc.)
- Includes structure field offsets (proc, ucred, filedesc)
- Sends output to log server on your PC
- Copy-paste format for easy use

**Usage:**

1. Edit `kernel_offsets.js` and set your PC's IP:
```javascript
const LOG_SERVER_IP = "192.168.1.100";  // Your PC's IP
const LOG_SERVER_PORT = 9023;
```

2. Start the log server on your PC:
```bash
python log_server.py
```

3. Send payload to PS5:
```bash
python payload_sender.py kernel_offsets.js
```

4. Check log server output for the dumped offsets

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
