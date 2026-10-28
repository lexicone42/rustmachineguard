//! The one YAML entry point. Every YAML document rmguard reads (skill, command and
//! subagent frontmatter, YAML MCP and agent configs, Serena's `project.yml`) can come
//! from a cloned repository, so the parser is attack surface: it is `serde-saphyr`
//! (`#![forbid(unsafe_code)]`), driven with an explicit budget instead of its defaults.
//!
//! Size is the first bound: rmguard's readers stop at [`MAX_CONFIG_SIZE`] and longer
//! input is refused here too. The node and event limits sit above what that much input
//! can hold (1 MiB of `[1,1,...]` is about 524k nodes; of `-\n`, 524k null nodes), so a
//! document without anchors is never refused for its size in nodes. What the other
//! limits cut short is amplification: anchors record events and aliases and merge keys
//! replay them, so their budgets stop an alias bomb ("billion laughs") or one large
//! scalar repeated through many aliases (the scalar-byte budget counts replays). Depth
//! bounds the recursion of the parser and of the value built: at the limit that is about
//! 450 KiB of stack in a release build (about 2.9 MiB unoptimised), on scanner threads
//! that have 8 MiB.
//!
//! Semantics (each a deliberate choice; see the regression tests in
//! `tests/yaml_hostile.rs`):
//! - YAML 1.2 core booleans: only `true`/`false` (any case) are booleans; `yes`, `on`,
//!   `y` stay strings, as the previous parser and the YAML 1.2 loaders agents use read
//!   them.
//! - Duplicate keys: the last value wins. A duplicate never hides the whole document.
//! - Merge keys (`<<: *base`) are expanded, so a hook or server defined through a
//!   merge is seen. Explicit keys win over merged ones.
//! - Tags are dropped: `!custom {x: 1}` reads as `{x: 1}`.
//! - `.nan` / `.inf` become `null`, as `serde_json` represents them.
//! - Keys are strings as written (`1: a` has key `"1"`); a null or empty key
//!   (`~: x`, `: x`, a bare `?`) is the key `""`, so it cannot make the document
//!   unreadable. A sequence or mapping used as a key is an error.
//! - Plain scalars that read as numbers are numbers: `0777` and `08080` are the floats
//!   777.0 and 8080.0 (serde_yaml_ng kept leading-zero forms as strings), `1_000` is
//!   1000, an integer past 64 bits is a float (it used to fail the whole document), and
//!   `1e999` is null. Detectors read strings, so quote a value to keep it one.
//! - One document only; a stream with a second document is an error.

use crate::scanners::MAX_CONFIG_SIZE;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, NonFiniteFloatPolicy, Options, RequireIndent};

/// Longest input accepted, in bytes: the readers' own cap.
pub const MAX_INPUT: usize = MAX_CONFIG_SIZE as usize;
/// Deepest nesting of sequences and mappings (block or flow). The previous parser
/// stopped at the same depth; real configs stay under ten.
pub const MAX_DEPTH: usize = 128;
/// Alias (`*ref`) uses in one document.
pub const MAX_ALIASES: usize = 10_000;
/// Events recorded for anchors, and events replayed from aliases, in one document (each
/// budget separately): 40 servers sharing a 500-event block. Real configs use a few hundred.
pub const MAX_REPLAYED_EVENTS: usize = 20_000;
/// Bytes of scalar text in one document, replayed aliases included: twice the input cap.
pub const MAX_SCALAR_BYTES: usize = 2 * MAX_INPUT;

/// Why a document was not read. A message can quote the input (a key, a scalar), so it
/// is for tests and debugging; scanners drop it.
#[derive(Debug)]
pub enum Error {
    /// Longer than [`MAX_INPUT`].
    TooLarge(usize),
    /// Not YAML, or over a budget.
    Yaml(Box<serde_saphyr::Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLarge(n) => write!(f, "YAML input of {n} bytes is over the {MAX_INPUT}-byte limit"),
            Error::Yaml(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

fn options() -> Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(MAX_INPUT),
            max_depth: MAX_DEPTH,
            flow_nesting_limit: MAX_DEPTH,
            // YAML's own implicit-key limit.
            simple_key_max_lookahead: 1024,
            max_documents: 1,
            max_nodes: 600_000,
            max_events: 1_500_000,
            max_total_scalar_bytes: MAX_SCALAR_BYTES,
            max_aliases: MAX_ALIASES,
            max_anchors: 50_000,
            max_recorded_anchor_events: MAX_REPLAYED_EVENTS,
            max_recorded_anchor_bytes: MAX_SCALAR_BYTES,
            max_merge_keys: 256,
            max_inclusion_depth: 0,
            enforce_alias_anchor_ratio: true,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: MAX_REPLAYED_EVENTS,
            max_replay_stack_depth: 16,
            max_alias_expansions_per_anchor: 1_000,
        },
        duplicate_keys: DuplicateKeyPolicy::LastWins,
        merge_keys: MergeKeyPolicy::Merge,
        strict_booleans: true,
        legacy_octal_numbers: false,
        no_schema: false,
        reject_unsupported_tags: false,
        non_finite_float_policy: NonFiniteFloatPolicy::PassThrough,
        require_indent: RequireIndent::Unchecked,
        with_snippet: false,
        crop_radius: 0,
    }
}

/// A YAML node as a `serde_json::Value`. `serde_json::Value`'s own `Deserialize` asks
/// for every key as a string, which a null key cannot be; this one reads keys as
/// [`Key`]. Recursion is bounded by [`MAX_DEPTH`].
struct Node(Value);

impl<'de> serde::Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NodeVisitor).map(Node)
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a YAML node")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Value, E> {
        Ok(Value::String(String::from_utf8_lossy(v).into_owned()))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Node(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(Key(k)) = map.next_key_seed(KeySeed)? {
            let Node(v) = map.next_value()?;
            // A repeated key: the last value wins (the parser already collapses most).
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

/// A mapping key: its text as written, or `""` for a null key.
struct Key(String);
struct KeySeed;

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = Key;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Key, D::Error> {
        // An optional string: null is `None`; any other scalar is its source text.
        <Option<String> as serde::Deserialize>::deserialize(d).map(|k| Key(k.unwrap_or_default()))
    }
}

/// Parse one YAML document into the JSON value model, within the budget above.
pub fn parse(content: &str) -> Result<Value, Error> {
    if content.len() > MAX_INPUT {
        return Err(Error::TooLarge(content.len()));
    }
    serde_saphyr::from_str_with_options::<Node>(content, options())
        .map(|Node(v)| v)
        .map_err(|e| Error::Yaml(Box::new(e)))
}

/// [`parse`], with any failure as `None`.
pub fn to_json(content: &str) -> Option<Value> {
    parse(content).ok()
}
