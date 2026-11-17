//! Tool catalog: BM25 keyword search and TypeScript-style signatures from JSON Schema.

use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub server: String,
    pub name: String,
    pub description: String,
    pub schema: Value,
    pub read_only: bool,
}

impl Entry {
    pub fn id(&self) -> String {
        format!("{}.{}", self.server, self.name)
    }

    pub fn signature(&self) -> String {
        let ty = ts_type(&self.schema, 0);
        let desc = self.description.trim().replace("*/", "* /");
        let doc = if desc.contains('\n') {
            format!(
                "/**\n{}\n */",
                desc.lines()
                    .map(|l| format!(" * {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            format!("/** {desc} */")
        };
        format!(
            "{doc}\n{}.{}(args: {ty}): Promise<any>",
            self.server, self.name
        )
    }
}

/// JSON Schema -> TypeScript type string (best effort).
pub fn ts_type(s: &Value, depth: usize) -> String {
    if depth > 6 {
        return "any".into();
    }
    if let Some(e) = s.get("enum").and_then(|e| e.as_array()) {
        return e
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(a) = s.get(key).and_then(|a| a.as_array()) {
            return a
                .iter()
                .map(|v| ts_type(v, depth + 1))
                .collect::<Vec<_>>()
                .join(" | ");
        }
    }
    match s.get("type") {
        Some(Value::Array(ts)) => ts
            .iter()
            .map(|t| {
                ts_type(
                    &serde_json::json!({ "type": t, "items": s.get("items") }),
                    depth + 1,
                )
            })
            .collect::<Vec<_>>()
            .join(" | "),
        Some(Value::String(t)) => match t.as_str() {
            "string" => "string".into(),
            "integer" | "number" => "number".into(),
            "boolean" => "boolean".into(),
            "null" => "null".into(),
            "array" => {
                let inner = s
                    .get("items")
                    .map_or("any".into(), |i| ts_type(i, depth + 1));
                format!("Array<{inner}>")
            }
            "object" => object_type(s, depth),
            _ => "any".into(),
        },
        _ if s.get("properties").is_some() => object_type(s, depth),
        _ => "any".into(),
    }
}

fn object_type(s: &Value, depth: usize) -> String {
    let Some(props) = s.get("properties").and_then(|p| p.as_object()) else {
        return "Record<string, any>".into();
    };
    let required: Vec<&str> = s
        .get("required")
        .and_then(|r| r.as_array())
        .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let fields: Vec<String> = props
        .iter()
        .map(|(k, v)| {
            let opt = if required.contains(&k.as_str()) {
                ""
            } else {
                "?"
            };
            format!("{k}{opt}: {}", ts_type(v, depth + 1))
        })
        .collect();
    format!("{{ {} }}", fields.join("; "))
}

fn tokenize(s: &str) -> Vec<String> {
    // Split on non-alphanumerics and camelCase boundaries.
    let mut out = vec![];
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_lowercase();
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    // Crude plural stemming so "item" matches "items" (applied to index and query alike).
    out.into_iter()
        .map(|t| {
            if t.len() > 3 && t.ends_with('s') && !t.ends_with("ss") {
                t[..t.len() - 1].to_string()
            } else {
                t
            }
        })
        .collect()
}

pub struct Catalog {
    pub entries: Vec<Entry>,
    docs: Vec<HashMap<String, f64>>,
    df: HashMap<String, f64>,
    avg_len: f64,
    lens: Vec<f64>,
}

impl Catalog {
    pub fn new(entries: Vec<Entry>) -> Self {
        let mut docs = vec![];
        let mut lens = vec![];
        let mut df: HashMap<String, f64> = HashMap::new();
        for e in &entries {
            // Name and server weigh more than the description.
            let mut tf: HashMap<String, f64> = HashMap::new();
            for t in tokenize(&format!("{} {}", e.server, e.name)) {
                *tf.entry(t).or_default() += 3.0;
            }
            for t in tokenize(&e.description) {
                *tf.entry(t).or_default() += 1.0;
            }
            lens.push(tf.values().sum());
            for k in tf.keys() {
                *df.entry(k.clone()).or_default() += 1.0;
            }
            docs.push(tf);
        }
        let avg_len = if lens.is_empty() {
            1.0
        } else {
            lens.iter().sum::<f64>() / lens.len() as f64
        };
        Catalog {
            entries,
            docs,
            df,
            avg_len,
            lens,
        }
    }

    pub fn get(&self, server: &str, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.server == server && e.name == name)
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<(&Entry, f64)> {
        let (k1, b) = (1.5, 0.75);
        let n = self.entries.len() as f64;
        let q = tokenize(query);
        let mut scored: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let score: f64 = q
                    .iter()
                    .map(|t| {
                        let f = self.docs[i].get(t).copied().unwrap_or(0.0);
                        if f == 0.0 {
                            return 0.0;
                        }
                        let df = self.df[t];
                        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                        idf * f * (k1 + 1.0)
                            / (f + k1 * (1.0 - b + b * self.lens[i] / self.avg_len))
                    })
                    .sum();
                (score > 0.0).then_some((e, score))
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.truncate(limit);
        scored
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn e(server: &str, name: &str, desc: &str) -> Entry {
        Entry {
            server: server.into(),
            name: name.into(),
            description: desc.into(),
            schema: json!({}),
            read_only: false,
        }
    }

    #[test]
    fn ts_signature() {
        let s = json!({"type":"object","required":["q"],"properties":{
            "q":{"type":"string"},"n":{"type":"integer"},
            "k":{"enum":["a","b"]},"t":{"type":"array","items":{"type":"string"}}}});
        assert_eq!(
            ts_type(&s, 0),
            r#"{ q: string; n?: number; k?: "a" | "b"; t?: Array<string> }"#
        );
    }

    #[test]
    fn bm25_ranks_name_match_first() {
        let c = Catalog::new(vec![
            e("gdrive", "listFiles", "List files in a folder"),
            e("slack", "postMessage", "Post a message to a channel"),
            e("gdrive", "getFile", "Fetch one file by id"),
        ]);
        let r = c.search("list files", 5);
        assert_eq!(r[0].0.id(), "gdrive.listFiles");
        assert_eq!(c.search("slack message", 1)[0].0.id(), "slack.postMessage");
        assert!(c.search("zzz", 5).is_empty());
        assert_eq!(c.search("message", 1)[0].0.id(), "slack.postMessage");
        assert_eq!(c.search("files", 3).len(), 2);
    }
}

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|f| f.is_alphabetic() || f == '_' || f == '$')
        && c.all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '$')
}

impl Catalog {
    /// TypeScript declarations for the sandbox globals (for editor tooling / prompting).
    pub fn dts(&self) -> String {
        let mut out = String::from(
            "// Generated by `omnix sdk`. Each upstream MCP server is a global in the `execute` sandbox.\n\
             // Binary results come back as { $handle, mimeType, size } and can be passed to other tools.\n\
             type Handle = { $handle: string; mimeType: string; size: number };\n\
             declare const state: Record<string, any>;\n\n",
        );
        let mut servers: Vec<&str> = self.entries.iter().map(|e| e.server.as_str()).collect();
        servers.dedup();
        servers.sort();
        servers.dedup();
        for s in servers {
            if !is_ident(s) {
                out.push_str(&format!(
                    "// server {s:?} is not a valid identifier; use globalThis[{s:?}]\n\n"
                ));
                continue;
            }
            out.push_str(&format!("declare const {s}: {{\n"));
            for e in self.entries.iter().filter(|e| e.server == s) {
                let desc = e
                    .description
                    .lines()
                    .next()
                    .unwrap_or("")
                    .replace("*/", "* /");
                if !desc.is_empty() {
                    out.push_str(&format!("  /** {desc} */\n"));
                }
                let name = if is_ident(&e.name) {
                    e.name.clone()
                } else {
                    format!("{:?}", e.name)
                };
                out.push_str(&format!(
                    "  {name}(args: {}): Promise<any>;\n",
                    ts_type(&e.schema, 0)
                ));
            }
            out.push_str("};\n\n");
        }
        out
    }
}

#[cfg(test)]
mod dts_tests {
    use super::*;

    #[test]
    fn emits_declarations() {
        let c = Catalog::new(vec![
            Entry {
                server: "gdrive".into(),
                name: "list".into(),
                description: "List */ files".into(),
                schema: serde_json::json!({"type":"object","properties":{"q":{"type":"string"}}}),
                read_only: true,
            },
            Entry {
                server: "my-srv".into(),
                name: "x".into(),
                description: String::new(),
                schema: serde_json::json!({}),
                read_only: false,
            },
            Entry {
                server: "gdrive".into(),
                name: "get-file".into(),
                description: String::new(),
                schema: serde_json::json!({}),
                read_only: false,
            },
        ]);
        let d = c.dts();
        assert!(d.contains("declare const gdrive: {"), "{d}");
        assert!(
            d.contains("list(args: { q?: string }): Promise<any>;"),
            "{d}"
        );
        assert!(d.contains("\"get-file\"(args: any)"), "{d}");
        assert!(
            d.contains("server \"my-srv\" is not a valid identifier"),
            "{d}"
        );
        assert!(
            !d.contains("*/ files"),
            "comment terminator must be escaped: {d}"
        );
    }
}
