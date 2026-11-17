//! Host-side binary handles: images/audio/blobs from upstream tools stay in host memory.
//! The sandbox and the model only ever see `{ "$handle": "h1", "mimeType": ..., "size": N }`.
//! A handle placed in the arguments of a later upstream call is replaced by its base64 data
//! on the host, so binary data can flow tool-to-tool without entering model context.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Mutex};

const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct HandleStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    total: usize,
    items: HashMap<String, (String, Vec<u8>)>,
}

impl HandleStore {
    /// Store base64 `data`; returns the JSON handle value.
    pub fn put_base64(&self, data: &str, mime: &str) -> Result<Value, String> {
        let bytes = STANDARD
            .decode(data)
            .map_err(|_| "upstream returned invalid base64".to_string())?;
        let mut g = self.inner.lock().unwrap();
        if g.total + bytes.len() > MAX_TOTAL_BYTES {
            return Err(format!(
                "binary handle store is full ({} MB limit)",
                MAX_TOTAL_BYTES >> 20
            ));
        }
        g.next += 1;
        let id = format!("h{}", g.next);
        let size = bytes.len();
        g.total += size;
        g.items.insert(id.clone(), (mime.to_string(), bytes));
        Ok(json!({"$handle": id, "mimeType": mime, "size": size}))
    }

    /// Replace every `{"$handle": id, ...}` object in `v` with the base64 data string.
    pub fn resolve(&self, v: &mut Value) -> Result<(), String> {
        match v {
            Value::Object(m) if m.get("$handle").is_some_and(|h| h.is_string()) => {
                let id = m["$handle"].as_str().unwrap().to_string();
                let g = self.inner.lock().unwrap();
                let (_, bytes) = g.items.get(&id).ok_or(format!("unknown handle {id}"))?;
                *v = Value::String(STANDARD.encode(bytes));
                Ok(())
            }
            Value::Object(m) => m.values_mut().try_for_each(|x| self.resolve(x)),
            Value::Array(a) => a.iter_mut().try_for_each(|x| self.resolve(x)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_resolve_roundtrip() {
        let s = HandleStore::default();
        let h = s.put_base64("aGVsbG8=", "text/plain").unwrap();
        assert_eq!(h["size"], 5);
        assert_eq!(h["mimeType"], "text/plain");
        let mut args = json!({"file": {"data": h.clone()}, "list": [h], "n": 1});
        s.resolve(&mut args).unwrap();
        assert_eq!(args["file"]["data"], "aGVsbG8=");
        assert_eq!(args["list"][0], "aGVsbG8=");
        assert!(s.resolve(&mut json!({"$handle": "h99"})).is_err());
        assert!(s.put_base64("***", "x").is_err());
    }
}
