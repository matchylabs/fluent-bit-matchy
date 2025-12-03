# Fluent Bit Matchy Filter Plugin

A WASM filter plugin that enriches Fluent Bit log streams with threat intelligence from [matchy](https://github.com/matchylabs/matchy) databases.

- Scans log records for IPs, domains, URLs, and file hashes
- Sub-millisecond lookups against `.mxy` threat databases
- Enriches matching records — never drops logs

## Installation

Download the [latest release](https://github.com/matchylabs/fluent-bit-matchy/releases) and extract it:

```bash
tar -xzf fluent-bit-matchy-v*.tar.gz
```

You'll get:
- `fluent_bit_matchy-VERSION.wasm` — the plugin
- `matchy.yaml.example` — plugin configuration template  
- `fluent-bit.yaml.example` — Fluent Bit configuration template

## Setup

Copy the files to your Fluent Bit directory:

```
/etc/fluent-bit/
├── fluent-bit.yaml
├── fluent_bit_matchy-0.2.0.wasm
├── matchy.yaml
└── threats.mxy
```

### matchy.yaml

```yaml
database: threats.mxy

# Auto-reload: check for updates every N seconds (0 = disabled)
reload_interval_secs: 30  # recommended if your threat feed updates frequently

# Optional: customize output field names
output_field: matchy_threats
flag_field: threat_detected

# Toggle extractors (all default to true)
extract_domains: true
extract_ipv4: true
extract_ipv6: true
extract_hashes: true
extract_emails: false
extract_bitcoin: false
extract_ethereum: false
extract_monero: false
```

### fluent-bit.yaml

```yaml
service:
  flush: 1
  log_level: info

pipeline:
  inputs:
    - name: tail
      path: /var/log/app.log
      tag: app

  filters:
    - name: wasm
      match: app
      wasm_path: fluent_bit_matchy-0.2.0.wasm
      function_name: matchy_filter
      accessible_paths: .
      wasm_heap_size: 256M

  outputs:
    - name: stdout
      match: "*"
```

**Notes:**
- `accessible_paths` must include the directory containing `matchy.yaml` and your `.mxy` database
- `wasm_heap_size` should be ~1.5x your database file size (it's loaded into memory)

## What it does

Input log:
```json
{"log": "Connection from 1.2.3.4 to malware.example.com"}
```

If `1.2.3.4` is in your threat database:
```json
{
  "log": "Connection from 1.2.3.4 to malware.example.com",
  "threat_detected": true,
  "matchy_threats": [
    {
      "indicator": "1.2.3.4",
      "type": "IPv4",
      "span": [17, 25],
      "result": {...}
    }
  ]
}
```

No match? The log passes through unchanged.

## Building threat databases

Use the [matchy CLI](https://github.com/matchylabs/matchy):

```bash
matchy build threats.csv -o threats.mxy
```

## Auto-reload

The plugin can automatically detect when your `.mxy` database file is updated and reload it — no restart required. This is disabled by default.

```yaml
# Enable auto-reload (check every 30 seconds)
reload_interval_secs: 30
```

Useful for threat intelligence feeds that update frequently. When you update your database file, the plugin picks up the changes within the configured interval.

## Performance

The plugin runs on any platform via Fluent Bit's WASM runtime.

Matchy uses SIMD for fast pattern matching. Whether SIMD is available depends on your Fluent Bit build:
- Most packaged builds (Homebrew, apt, etc.) run WASM in interpreter mode without SIMD — still fast, but not optimal
- For maximum performance, AOT-compile the WASM for your CPU using `flb-wamrc` (requires building Fluent Bit with `-DFLB_WAMRC=On`)

For most workloads, the interpreter is plenty fast.

## Building from source

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
# Output: target/wasm32-wasip1/release/fluent_bit_matchy.wasm
```

## License

Apache-2.0
