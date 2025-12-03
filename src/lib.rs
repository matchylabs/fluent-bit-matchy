//! Fluent Bit WASM Filter Plugin for Matchy
//!
//! Real-time threat intelligence enrichment for log streams.
//! Scans logs for IoCs and adds threat data when matches are found.
//! All logs pass through - records are enriched, never dropped.
//!
//! ## Configuration
//!
//! Create `matchy.yaml` next to your `fluent-bit.yaml`:
//!
//! ```yaml
//! database: ./threats.mxy
//!
//! # Output field names (optional)
//! output_field: matchy_threats    # where match details go
//! flag_field: threat_detected     # boolean flag added on match
//!
//! # Extractor toggles (default: true)
//! extract_domains: true
//! extract_ipv4: true
//! extract_ipv6: true
//! extract_hashes: true
//! extract_emails: false
//! extract_bitcoin: false
//! extract_ethereum: false
//! extract_monero: false
//! ```
//!
//! Fluent Bit config:
//!
//! ```yaml
//! pipeline:
//!   filters:
//!     - name: wasm
//!       match: "*"
//!       wasm_path: /path/to/fluent_bit_matchy.wasm
//!       function_name: matchy_filter
//!       accessible_paths: .
//! ```

use matchy::{Database, QueryResult};
use matchy_extractor::Extractor;
use serde::Deserialize;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::slice;

/// Config file name (YAML)
const CONFIG_FILE: &str = "matchy.yaml";

/// Plugin configuration
#[derive(Debug, Deserialize, Clone)]
struct Config {
    /// Path to the matchy database (.mxy file)
    database: String,

    /// Field name for match results (default: "matchy_threats")  
    #[serde(default = "default_output_field")]
    output_field: String,

    /// Field name for threat detected flag (default: "threat_detected")
    #[serde(default = "default_flag_field")]
    flag_field: String,

    /// Extractor toggles
    #[serde(default = "default_true")] extract_domains: bool,
    #[serde(default = "default_true")] extract_emails: bool,
    #[serde(default = "default_true")] extract_ipv4: bool,
    #[serde(default = "default_true")] extract_ipv6: bool,
    #[serde(default = "default_true")] extract_hashes: bool,
    #[serde(default = "default_true")] extract_bitcoin: bool,
    #[serde(default = "default_true")] extract_ethereum: bool,
    #[serde(default = "default_true")] extract_monero: bool,
}

fn default_output_field() -> String {
    "matchy_threats".to_string()
}
fn default_flag_field() -> String {
    "threat_detected".to_string()
}
fn default_true() -> bool { true }

/// Filter state
struct FilterState {
    config: Option<Config>,
    database: Option<Database>,
    extractor: Option<Extractor>,
    initialized: bool,
}

impl FilterState {
    fn new() -> Self {
        Self {
            config: None,
            database: None,
            extractor: None,
            initialized: false,
        }
    }

    fn initialize(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;

        // Load configuration (YAML)
        let Some(config) = load_config() else {
            eprintln!("[matchy] ERROR: No config found. Create {}.", CONFIG_FILE);
            eprintln!("[matchy] Example {}:\ndatabase: ./threats.mxy", CONFIG_FILE);
            return;
        };

        // Initialize extractor from config
        let extractor = match Extractor::builder()
            .extract_domains(config.extract_domains)
            .extract_emails(config.extract_emails)
            .extract_ipv4(config.extract_ipv4)
            .extract_ipv6(config.extract_ipv6)
            .extract_hashes(config.extract_hashes)
            .extract_bitcoin(config.extract_bitcoin)
            .extract_ethereum(config.extract_ethereum)
            .extract_monero(config.extract_monero)
            .build() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[matchy] ERROR: Failed to create extractor: {}", e);
                return;
            }
        };

        // Load database
        match std::fs::read(&config.database) {
            Ok(bytes) => {
                let size_mb = bytes.len() as f64 / (1024.0 * 1024.0);
                match Database::from_bytes(bytes) {
                    Ok(db) => {
                        eprintln!(
                            "[matchy] Loaded {} ({:.1} MB)",
                            config.database, size_mb
                        );
                        self.database = Some(db);
                        self.extractor = Some(extractor);
                        self.config = Some(config);
                    }
                    Err(e) => {
                        eprintln!("[matchy] ERROR: Failed to parse {}: {}", config.database, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("[matchy] ERROR: Cannot read {}: {}", config.database, e);
            }
        }
    }
}

/// Load YAML config from matchy.yaml
fn load_config() -> Option<Config> {
    let contents = std::fs::read_to_string(CONFIG_FILE).ok()?;
    match serde_yaml::from_str(&contents) {
        Ok(config) => Some(config),
        Err(e) => {
            eprintln!("[matchy] ERROR: Failed to parse {}: {}", CONFIG_FILE, e);
            None
        }
    }
}

thread_local! {
    static STATE: RefCell<FilterState> = RefCell::new(FilterState::new());
}

/// Result buffer for WASM FFI
static mut RESULT_BUFFER: Vec<u8> = Vec::new();

/// Helper to return record unchanged (pass-through)
#[inline]
fn pass_through(record_slice: &[u8]) -> *const u8 {
    unsafe {
        RESULT_BUFFER = record_slice.to_vec();
        RESULT_BUFFER.push(0);
        RESULT_BUFFER.as_ptr()
    }
}

/// Main filter function called by Fluent Bit
/// 
/// Behavior:
/// - Always passes through all records (never drops)
/// - Scans entire record for IoCs using the extractor
/// - On match: adds threat_detected=true and matchy_threats=[...] fields
/// - On no match: record passes through unchanged
#[no_mangle]
pub extern "C" fn filter(
    _tag: *const u8,
    _tag_len: u32,
    _time_sec: u32,
    _time_nsec: u32,
    record: *const u8,
    record_len: u32,
) -> *const u8 {
    let record_slice = unsafe { slice::from_raw_parts(record, record_len as usize) };

    // Try to parse as JSON for enrichment, but always pass through
    let record_json: Option<Value> = serde_json::from_slice(record_slice).ok();

    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.initialize();

        let (db, config, extractor) = match (&state.database, &state.config, &state.extractor) {
            (Some(db), Some(cfg), Some(ext)) => (db, cfg, ext),
            // Not initialized -> pass through unchanged
            _ => return pass_through(record_slice),
        };

        // Extract IoCs from the entire record bytes
        let extracted = extractor.extract_from_chunk(record_slice);
        if extracted.is_empty() {
            // No IoCs found -> pass through unchanged
            return pass_through(record_slice);
        }

        // Query database for each extracted IoC
        let mut matches: Vec<Value> = Vec::new();
        for m in extracted {
            let indicator = m.item.as_value();
            if let Ok(Some(result)) = db.lookup(&indicator) {
                let data = match &result {
                    QueryResult::Ip { data, prefix_len } => json!({
                        "data": format!("{:?}", data),
                        "prefix_len": prefix_len,
                    }),
                    QueryResult::Pattern { pattern_ids, data } => json!({
                        "pattern_ids": pattern_ids,
                        "data": data.iter().map(|d| format!("{:?}", d)).collect::<Vec<_>>(),
                    }),
                    QueryResult::NotFound => continue,
                };
                matches.push(json!({
                    "indicator": indicator,
                    "type": m.item.type_name(),
                    "span": [m.span.0, m.span.1],
                    "result": data,
                }));
            }
        }

        if matches.is_empty() {
            // IoCs found but none in database -> pass through unchanged
            return pass_through(record_slice);
        }

        // Enrich record if we have JSON, otherwise pass through unchanged
        // (We need a JSON object to add fields to)
        let Some(mut record_json) = record_json else {
            return pass_through(record_slice);
        };

        if let Some(obj) = record_json.as_object_mut() {
            obj.insert(config.flag_field.clone(), json!(true));
            obj.insert(config.output_field.clone(), json!(matches));
        } else {
            // Not a JSON object -> pass through unchanged
            return pass_through(record_slice);
        }

        // Return enriched record
        match serde_json::to_vec(&record_json) {
            Ok(output) => {
                unsafe {
                    RESULT_BUFFER = output;
                    RESULT_BUFFER.push(0);
                    RESULT_BUFFER.as_ptr()
                }
            }
            // Serialization failed -> pass through unchanged
            Err(_) => pass_through(record_slice),
        }
    })
}
