//! Just enough of the PostgreSQL v3 wire protocol to see the statements go by
//! and to refuse one politely.
//!
//! Deliberately not a full implementation. The proxy relays every message it
//! does not care about byte for byte, so the parts modelled here are only:
//!
//! * the startup phase, because SSL negotiation happens before framing starts
//! * `Query` and `Parse`, because those carry SQL
//! * `ErrorResponse` and `ReadyForQuery`, because refusing has to look to the
//!   client like an ordinary permission error rather than a dropped connection
//!
//! Everything else is opaque bytes, which is what keeps this small enough to
//! reason about.

use std::io::{self, Read, Write};

/// `SSLRequest` — sent before any normal framing exists.
pub const SSL_REQUEST_CODE: i32 = 80_877_103;
/// `CancelRequest`.
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;
/// `GSSENCRequest`.
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;

/// SQLSTATE `insufficient_privilege`.
///
/// The honest code for what happened: the client is not authorized to run this,
/// pending something it has not got. Inventing a bespoke error would only mean
/// every driver in the world renders it as "unknown".
pub const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

/// One framed protocol message: a type byte and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub tag: u8,
    pub body: Vec<u8>,
}

impl Message {
    /// Re-encode for relaying: tag, length (inclusive of itself), body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.body.len());
        out.push(self.tag);
        out.extend_from_slice(&((self.body.len() + 4) as i32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// The SQL this message carries, if any.
    ///
    /// `Query` is the simple protocol. `Parse` is the extended one, which is
    /// what most drivers and every ORM actually emit — a proxy that only
    /// inspected `Query` would watch a `DROP TABLE` go past untouched because
    /// psycopg used a prepared statement.
    pub fn sql(&self) -> Option<String> {
        match self.tag {
            b'Q' => read_cstring(&self.body, 0).map(|(sql, _)| sql),
            b'P' => {
                // Parse: statement name, then the query text.
                let (_name, after) = read_cstring(&self.body, 0)?;
                read_cstring(&self.body, after).map(|(sql, _)| sql)
            }
            _ => None,
        }
    }

    /// Whether this ends an extended-protocol exchange.
    ///
    /// After an error the server discards messages until `Sync`, then reports
    /// `ReadyForQuery`. A proxy that refuses a `Parse` has to imitate that or
    /// the client waits forever for a reply that is never coming.
    pub fn is_sync(&self) -> bool {
        self.tag == b'S'
    }

    /// Whether this ends the session.
    pub fn is_terminate(&self) -> bool {
        self.tag == b'X'
    }
}

/// Read one framed message. `Ok(None)` at a clean end of stream.
pub fn read_message(reader: &mut impl Read) -> io::Result<Option<Message>> {
    let mut tag = [0u8; 1];
    match reader.read_exact(&mut tag) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let length = read_i32(reader)?;
    if !(4..=MAX_MESSAGE).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "implausible message length {length} for tag {}",
                tag[0] as char
            ),
        ));
    }

    let mut body = vec![0u8; (length - 4) as usize];
    reader.read_exact(&mut body)?;
    Ok(Some(Message { tag: tag[0], body }))
}

/// A ceiling on message size, so a corrupt length cannot make us allocate the
/// machine's memory before we notice.
const MAX_MESSAGE: i32 = 64 * 1024 * 1024;

/// The client's opening message, which has no tag byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// `SSLRequest` / `GSSENCRequest`: a negotiation we answer with one byte.
    Negotiation(i32),
    /// A real startup packet, relayed as-is.
    Packet(Vec<u8>),
    /// `CancelRequest`, relayed as-is.
    Cancel(Vec<u8>),
}

/// Read the untagged startup message.
pub fn read_startup(reader: &mut impl Read) -> io::Result<Startup> {
    let length = read_i32(reader)?;
    if !(8..=MAX_MESSAGE).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("implausible startup length {length}"),
        ));
    }

    let mut body = vec![0u8; (length - 4) as usize];
    reader.read_exact(&mut body)?;

    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if length == 8 && (code == SSL_REQUEST_CODE || code == GSSENC_REQUEST_CODE) {
        return Ok(Startup::Negotiation(code));
    }
    if code == CANCEL_REQUEST_CODE {
        return Ok(Startup::Cancel(prefix_length(&body)));
    }
    Ok(Startup::Packet(prefix_length(&body)))
}

fn prefix_length(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// An `ErrorResponse` the client will render as an ordinary error.
pub fn error_response(message: &str, detail: Option<&str>, hint: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    let mut field = |code: u8, text: &str| {
        body.push(code);
        body.extend_from_slice(text.as_bytes());
        body.push(0);
    };

    field(b'S', "ERROR");
    field(b'V', "ERROR");
    field(b'C', SQLSTATE_INSUFFICIENT_PRIVILEGE);
    field(b'M', message);
    if let Some(detail) = detail {
        field(b'D', detail);
    }
    if let Some(hint) = hint {
        field(b'H', hint);
    }
    body.push(0); // terminator

    Message { tag: b'E', body }.encode()
}

/// `ReadyForQuery`. `'I'` idle, `'T'` in a transaction, `'E'` failed transaction.
pub fn ready_for_query(status: u8) -> Vec<u8> {
    Message {
        tag: b'Z',
        body: vec![status],
    }
    .encode()
}

fn read_i32(reader: &mut impl Read) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(i32::from_be_bytes(buf))
}

/// Read a null-terminated string, returning it and the offset just past it.
fn read_cstring(body: &[u8], from: usize) -> Option<(String, usize)> {
    let end = body[from..].iter().position(|b| *b == 0)? + from;
    let text = String::from_utf8_lossy(&body[from..end]).into_owned();
    Some((text, end + 1))
}

/// Write all of `bytes` and flush.
pub fn write_all(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(sql: &str) -> Vec<u8> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        Message { tag: b'Q', body }.encode()
    }

    fn parse(name: &str, sql: &str) -> Vec<u8> {
        let mut body = name.as_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);
        body.extend_from_slice(&0i16.to_be_bytes());
        Message { tag: b'P', body }.encode()
    }

    #[test]
    fn a_simple_query_round_trips_and_yields_its_sql() {
        let wire = query("SELECT 1");
        let message = read_message(&mut wire.as_slice()).unwrap().unwrap();
        assert_eq!(message.tag, b'Q');
        assert_eq!(message.sql().unwrap(), "SELECT 1");
        assert_eq!(message.encode(), wire, "relaying must be byte-exact");
    }

    #[test]
    fn an_extended_protocol_parse_yields_its_sql_too() {
        // The case a proxy that only watched `Query` would miss entirely —
        // which is most real traffic, because every ORM prepares statements.
        let wire = parse("stmt_1", "DROP TABLE users");
        let message = read_message(&mut wire.as_slice()).unwrap().unwrap();
        assert_eq!(message.tag, b'P');
        assert_eq!(message.sql().unwrap(), "DROP TABLE users");
        assert_eq!(message.encode(), wire);
    }

    #[test]
    fn an_unnamed_prepared_statement_still_yields_its_sql() {
        // The unnamed statement is the common case: an empty name, then the
        // query. An off-by-one here would silently stop inspecting everything.
        let wire = parse("", "DELETE FROM orders");
        let message = read_message(&mut wire.as_slice()).unwrap().unwrap();
        assert_eq!(message.sql().unwrap(), "DELETE FROM orders");
    }

    #[test]
    fn messages_that_carry_no_sql_say_so() {
        for tag in [b'B', b'E', b'S', b'X', b'D'] {
            let message = Message { tag, body: vec![0] };
            assert_eq!(message.sql(), None, "tag {}", tag as char);
        }
    }

    #[test]
    fn several_messages_read_in_sequence() {
        let mut wire = query("SELECT 1");
        wire.extend(parse("s", "SELECT 2"));
        wire.extend(
            Message {
                tag: b'S',
                body: vec![],
            }
            .encode(),
        );

        let mut cursor = wire.as_slice();
        assert_eq!(
            read_message(&mut cursor).unwrap().unwrap().sql().unwrap(),
            "SELECT 1"
        );
        assert_eq!(
            read_message(&mut cursor).unwrap().unwrap().sql().unwrap(),
            "SELECT 2"
        );
        assert!(read_message(&mut cursor).unwrap().unwrap().is_sync());
        assert!(
            read_message(&mut cursor).unwrap().is_none(),
            "clean end of stream"
        );
    }

    #[test]
    fn a_corrupt_length_is_refused_rather_than_allocated() {
        // Otherwise a hostile or confused client makes the proxy allocate
        // whatever it likes before anything notices.
        let mut wire = vec![b'Q'];
        wire.extend_from_slice(&i32::MAX.to_be_bytes());
        assert!(read_message(&mut wire.as_slice()).is_err());

        let mut short = vec![b'Q'];
        short.extend_from_slice(&1i32.to_be_bytes());
        assert!(read_message(&mut short.as_slice()).is_err());
    }

    #[test]
    fn an_ssl_request_is_recognised_before_framing_starts() {
        let mut wire = 8i32.to_be_bytes().to_vec();
        wire.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        assert_eq!(
            read_startup(&mut wire.as_slice()).unwrap(),
            Startup::Negotiation(SSL_REQUEST_CODE)
        );
    }

    #[test]
    fn a_startup_packet_is_relayed_with_its_length_intact() {
        let mut payload = 196_608i32.to_be_bytes().to_vec(); // protocol 3.0
        payload.extend_from_slice(b"user\0alice\0\0");
        let mut wire = ((payload.len() + 4) as i32).to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);

        let Startup::Packet(relayed) = read_startup(&mut wire.as_slice()).unwrap() else {
            panic!("expected a startup packet");
        };
        assert_eq!(relayed, wire, "the upstream must see exactly what arrived");
    }

    #[test]
    fn a_cancel_request_is_distinguished_from_a_startup() {
        let mut payload = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
        payload.extend_from_slice(&1234i32.to_be_bytes());
        payload.extend_from_slice(&5678i32.to_be_bytes());
        let mut wire = ((payload.len() + 4) as i32).to_be_bytes().to_vec();
        wire.extend_from_slice(&payload);

        assert!(matches!(
            read_startup(&mut wire.as_slice()).unwrap(),
            Startup::Cancel(_)
        ));
    }

    #[test]
    fn a_refusal_looks_like_an_ordinary_permission_error() {
        // A dropped connection would be read as a network fault and retried.
        // An error the client understands stops it.
        let wire = error_response("countersign: not approved", Some("detail"), Some("hint"));
        let message = read_message(&mut wire.as_slice()).unwrap().unwrap();
        assert_eq!(message.tag, b'E');

        let text = String::from_utf8_lossy(&message.body);
        assert!(text.contains(SQLSTATE_INSUFFICIENT_PRIVILEGE));
        assert!(text.contains("countersign: not approved"));
        assert!(text.contains("detail"));
        assert!(text.contains("hint"));
        assert_eq!(*message.body.last().unwrap(), 0, "field list is terminated");
    }

    #[test]
    fn ready_for_query_reports_the_transaction_state() {
        let wire = ready_for_query(b'I');
        let message = read_message(&mut wire.as_slice()).unwrap().unwrap();
        assert_eq!(message.tag, b'Z');
        assert_eq!(message.body, vec![b'I']);
    }

    #[test]
    fn non_ascii_sql_survives_extraction() {
        let wire = query("SELECT * FROM café WHERE naïve = 'x'");
        let message = read_message(&mut wire.as_slice()).unwrap().unwrap();
        assert_eq!(
            message.sql().unwrap(),
            "SELECT * FROM café WHERE naïve = 'x'"
        );
    }
}
