//! JSON-RPC 2.0 envelopes, line-delimited. See `spec/pack-protocol-v1.md` §2.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC error codes, plus the ones this protocol adds.
pub mod code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl RpcRequest {
    pub fn new(id: u64, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Value::from(id),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_carries_result_or_error_but_not_both_fields() {
        let ok = serde_json::to_string(&RpcResponse::ok(Value::from(1), Value::Null)).unwrap();
        assert!(!ok.contains("error"), "got {ok}");

        let bad =
            serde_json::to_string(&RpcResponse::err(Value::from(1), code::PARSE_ERROR, "nope"))
                .unwrap();
        assert!(!bad.contains("result"), "got {bad}");
        assert!(bad.contains("-32700"));
    }

    #[test]
    fn envelopes_round_trip() {
        let req = RpcRequest::new(7, "classify", Some(serde_json::json!({"a": 1})));
        let line = serde_json::to_string(&req).unwrap();
        assert!(!line.contains('\n'), "framing is one message per line");
        assert_eq!(serde_json::from_str::<RpcRequest>(&line).unwrap(), req);
    }
}
