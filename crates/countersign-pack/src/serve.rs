//! The pack side: implement [`Pack`], call [`run_stdio`], you are done.

use std::io::{self, BufRead, Write};

use serde_json::Value;

use crate::rpc::{code, RpcRequest, RpcResponse};
use crate::types::{ClassifyRequest, ClassifyResponse, PackInfo};

/// A domain pack: it knows what a statement in its namespace actually does.
///
/// Implementations should be pure — no I/O, no network, no clock. `statement`
/// is production text containing table names and literal values, which means it
/// contains customer data. A pack that phones home has quietly turned an
/// approval prompt into an exfiltration channel, and it would do so on precisely
/// the statements the operator cared enough to gate.
pub trait Pack {
    fn describe(&self) -> PackInfo;

    /// Classify a statement.
    ///
    /// Return the most severe honest answer. A pack cannot lower the host's
    /// floor, so guessing low buys nothing and guessing high costs one dial
    /// turn — the asymmetry is deliberate, and it should shape what you return
    /// when you are unsure.
    fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse;
}

/// Serve a pack over stdin/stdout until EOF.
///
/// Never writes anything to stdout that is not a response — a pack that prints
/// a startup banner has broken the transport. Log to stderr.
pub fn run_stdio<P: Pack + ?Sized>(pack: &P) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(pack, &line);
        // One message per line, flushed immediately: the host is a human's
        // approval prompt waiting on this, not a batch job.
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }
    Ok(())
}

/// Dispatch one request line. Exposed for tests — it is the whole protocol.
pub fn handle_line<P: Pack + ?Sized>(pack: &P, line: &str) -> RpcResponse {
    let request: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return RpcResponse::err(Value::Null, code::PARSE_ERROR, e.to_string()),
    };

    if request.jsonrpc != "2.0" {
        return RpcResponse::err(
            request.id,
            code::INVALID_REQUEST,
            format!("unsupported jsonrpc version {:?}", request.jsonrpc),
        );
    }

    match request.method.as_str() {
        "describe" => match serde_json::to_value(pack.describe()) {
            Ok(v) => RpcResponse::ok(request.id, v),
            Err(e) => RpcResponse::err(request.id, code::INTERNAL_ERROR, e.to_string()),
        },
        "classify" => {
            let params = match request.params {
                Some(p) => p,
                None => {
                    return RpcResponse::err(
                        request.id,
                        code::INVALID_PARAMS,
                        "classify requires params",
                    )
                }
            };
            let req: ClassifyRequest = match serde_json::from_value(params) {
                Ok(r) => r,
                Err(e) => return RpcResponse::err(request.id, code::INVALID_PARAMS, e.to_string()),
            };
            match serde_json::to_value(pack.classify(&req)) {
                Ok(v) => RpcResponse::ok(request.id, v),
                Err(e) => RpcResponse::err(request.id, code::INTERNAL_ERROR, e.to_string()),
            }
        }
        other => RpcResponse::err(
            request.id,
            code::METHOD_NOT_FOUND,
            format!("unknown method {other:?}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RenderLine, Severity, PROTOCOL};

    struct Stub;

    impl Pack for Stub {
        fn describe(&self) -> PackInfo {
            PackInfo {
                name: "stub".into(),
                version: "0.1.0".into(),
                protocol: PROTOCOL,
                actions: vec!["sql".into()],
                pure: true,
            }
        }
        fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse {
            let mut r = ClassifyResponse::new("sql.ddl", Severity::Critical);
            r.render.push(RenderLine::primary(req.statement.clone()));
            r
        }
    }

    fn call(line: &str) -> RpcResponse {
        handle_line(&Stub, line)
    }

    #[test]
    fn describe_returns_the_packs_identity() {
        let r = call(r#"{"jsonrpc":"2.0","id":1,"method":"describe"}"#);
        let info: PackInfo = serde_json::from_value(r.result.unwrap()).unwrap();
        assert_eq!(info.name, "stub");
        assert_eq!(info.protocol, PROTOCOL);
    }

    #[test]
    fn classify_round_trips_a_statement() {
        let r = call(
            r#"{"jsonrpc":"2.0","id":2,"method":"classify",
                "params":{"action":"sql.execute","statement":"DROP TABLE t"}}"#,
        );
        let resp: ClassifyResponse = serde_json::from_value(r.result.unwrap()).unwrap();
        assert_eq!(resp.severity, Severity::Critical);
        assert_eq!(resp.render[0].text, "DROP TABLE t");
    }

    #[test]
    fn malformed_input_gets_an_error_not_a_panic() {
        // A pack that dies on bad input takes the approval prompt down with it.
        assert_eq!(call("not json").error.unwrap().code, code::PARSE_ERROR);
        assert_eq!(
            call(r#"{"jsonrpc":"1.0","id":1,"method":"describe"}"#)
                .error
                .unwrap()
                .code,
            code::INVALID_REQUEST
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#)
                .error
                .unwrap()
                .code,
            code::METHOD_NOT_FOUND
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"classify"}"#)
                .error
                .unwrap()
                .code,
            code::INVALID_PARAMS
        );
    }

    #[test]
    fn a_parse_error_still_answers_with_a_null_id() {
        // The host is waiting on a line; silence would hang it until timeout.
        assert_eq!(call("{{{").id, Value::Null);
    }

    #[test]
    fn responses_are_always_one_line() {
        let r = call(
            r#"{"jsonrpc":"2.0","id":3,"method":"classify",
                "params":{"action":"sql.execute","statement":"SELECT\n1"}}"#,
        );
        let line = serde_json::to_string(&r).unwrap();
        assert!(
            !line.contains('\n'),
            "a newline in the payload must not break framing"
        );
    }
}
