# Fluent Bit Matchy Filter Plugin

Real-time threat intelligence enrichment for Fluent Bit log streams using [matchy](https://github.com/matchylabs/matchy).

## Features

- Scans entire log records for IoCs (IPs, domains, hashes, etc.)
- Sub-millisecond lookups against matchy threat databases
- Enriches records with threat data — never drops logs
- Simple YAML configuration

## Installation

### Build from source

```bash
# Install WASM target
rustup target add wasm32-wasip1

# Build
cargo build --target wasm32-wasip1 --release

# Output: target/wasm32-wasip1/release/fluent_bit_matchy.wasm
```

## Configuration

### 1. Create `matchy.yaml`

Place in the same directory as your Fluent Bit config:

```yaml
database: /etc/fluent-bit/threats.mxy

# Optional: customize output field names
output_field: matchy_threats
flag_field: threat_detected

# Optional: toggle extractors (all default to true)
extract_domains: true
extract_ipv4: true
extract_ipv6: true
extract_hashes: true
extract_emails: false
extract_bitcoin: false
extract_ethereum: false
extract_monero: false
```

### 2. Configure Fluent Bit

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
      wasm_path: /usr/lib/fluent-bit/fluent_bit_matchy.wasm
      function_name: matchy_filter
      accessible_paths: /etc/fluent-bit
      wasm_heap_size: 256M

  outputs:
    - name: stdout
      match: "*"
```

**Important**: 
- `accessible_paths` must include the directory containing both `matchy.yaml` and your `.mxy` database
- `wasm_heap_size` must be larger than your database file size (the database is loaded into memory, plus overhead for processing). A good rule of thumb: set it to ~1.5x your `.mxy` file size

## Example

### Directory layout

```
/etc/fluent-bit/
├── fluent-bit.yaml
├── matchy.yaml
└── threats.mxy
```

### Behavior

Input log:
```json
{"log": "Connection from 1.2.3.4 to malware.example.com"}
```

If `1.2.3.4` is in your threat database, output becomes:
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

If no threats match, the log passes through unchanged.

## Building Threat Databases

```bash
matchy build threats.csv -o threats.mxy
```

## Performance

The plugin ships as a portable `.wasm` file that runs on any platform via Fluent Bit's WASM interpreter.

**SIMD support**: Matchy uses SIMD instructions for fast pattern matching. Whether these are used depends on your Fluent Bit build:
- Most packaged builds (Homebrew, apt, etc.) run WASM in interpreter mode without SIMD — still fast, but not optimal
- For maximum performance, you can AOT-compile the WASM for your target CPU using `flb-wamrc` (requires building Fluent Bit with `-DFLB_WAMRC=On`)

For most workloads, the interpreter is plenty fast. AOT compilation is only worth pursuing for very high-throughput deployments.

## License

Apache-2.0
