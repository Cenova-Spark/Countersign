//! SQL *lexical* scanning — where does real SQL stop and inert text begin?
//!
//! Almost every SQL utility needs the same single question answered: is the
//! character I'm looking at real SQL, or is it text inside a string literal, a
//! quoted identifier, a comment, or a `$tag$` dollar-quoted body? A `;` inside a
//! function body doesn't end a statement; a `DROP` inside a string isn't a write.
//!
//! [`Scan`] walks the text once and yields [`Span`]s tagged by [`Region`]; every
//! consumer in this crate differs only in what it *does* with a span. That
//! sharing is the point — two hand-written copies of this walk drift, and when
//! they drift the statement a classifier blocks is not the statement a splitter
//! executes.
//!
//! It is a scanner, not a parser — it knows where regions begin and end and
//! nothing about grammar. Execution still hands the original text to the driver
//! verbatim.
//!
//! ## Provenance
//!
//! This module and [`crate::classify`] began life as `core/src/sql_text.rs` and
//! `core/src/safety.rs` in AddisDB, where they back the read-only connection
//! gate. They are relicensed here under Apache 2.0 by their copyright holder so
//! that one implementation serves both. Keeping it one implementation is a
//! security property, not tidiness: a classifier that disagrees with the gate in
//! front of it waves through exactly the statement the gate would have blocked.
//!
//! ## Backslashes
//!
//! Whether `\'` escapes a quote is dialect-specific, so it is a parameter of the
//! scan rather than a behavior baked into it — see [`BackslashEscapes`].

/// What a scanned span covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Ordinary SQL. The only region where a `;` splits or a keyword counts.
    Code,
    /// `--` through end of line (the newline itself is left as `Code`).
    LineComment,
    /// `/* … */`, including both delimiters.
    BlockComment,
    /// `'…'` or `"…"`, including the quotes.
    Quoted,
    /// `$tag$…$tag$`, including both tags.
    DollarQuoted,
}

impl Region {
    /// Whether this region is executable SQL rather than inert text.
    pub fn is_code(self) -> bool {
        self == Region::Code
    }
}

/// One contiguous region of the input, as byte offsets into the source string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub region: Region,
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

/// How a single-quoted string treats a backslash.
///
/// The two callers genuinely need opposite answers, because the SQL dialects do:
///
/// * MySQL (and friends) treat `\'` as an escaped quote, so a scanner that
///   ignores backslashes stops the string early and mistakes the rest of the
///   literal for executable SQL.
/// * PostgreSQL with `standard_conforming_strings` on — the default — treats `\`
///   as an ordinary character, so a scanner that honors it runs *past* the real
///   closing quote and swallows whatever follows.
///
/// Whichever way a single scanner jumped, it would be wrong for one family. So
/// the choice is the caller's:
///
/// * [`split_on_semicolons`] uses [`Ignore`](BackslashEscapes::Ignore) — merging
///   two statements into one is a visible failure the database rejects.
/// * [`blank_non_code`] is asked for *both*, one reading after the other:
///   [`crate::classify::analyze`] classifies each and gates on the stronger verdict, so a
///   write that either dialect can see is never waved through — see the note on
///   that function.
///
/// Do not "simplify" this into a single behavior without reading both tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackslashEscapes {
    /// `\'` continues the string (MySQL-style).
    Honor,
    /// `\` is an ordinary character (standard-conforming SQL).
    Ignore,
}

/// If a dollar-quote opener (`$tag$`, tag is `[A-Za-z0-9_]*`) starts at `i`,
/// return the byte index of its closing `$`.
fn dollar_tag_end(b: &[u8], i: usize) -> Option<usize> {
    debug_assert_eq!(b[i], b'$');
    let mut j = i + 1;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
        j += 1;
    }
    (j < b.len() && b[j] == b'$').then_some(j)
}

/// Walks SQL once, yielding [`Span`]s. Adjacent `Code` bytes are coalesced into
/// a single span, so a statement with no literals yields exactly one.
pub struct Scan<'a> {
    sql: &'a str,
    b: &'a [u8],
    i: usize,
    esc: BackslashEscapes,
}

/// Scan `sql`, deciding backslash handling per `esc`.
pub fn scan(sql: &str, esc: BackslashEscapes) -> Scan<'_> {
    Scan {
        sql,
        b: sql.as_bytes(),
        i: 0,
        esc,
    }
}

impl<'a> Scan<'a> {
    /// Does a non-code region open at `i`?
    fn opens_special(&self, i: usize) -> bool {
        let b = self.b;
        match b[i] {
            b'-' => i + 1 < b.len() && b[i + 1] == b'-',
            b'/' => i + 1 < b.len() && b[i + 1] == b'*',
            b'\'' | b'"' => true,
            // A lone `$` (e.g. a `$1` placeholder) is ordinary code.
            b'$' => dollar_tag_end(b, i).is_some(),
            _ => false,
        }
    }

    /// Consume the non-code construct starting at `self.i`, returning its span.
    fn take_special(&mut self) -> Span {
        let b = self.b;
        let start = self.i;
        let c = b[start];

        // line comment: -- … (stops before the newline)
        if c == b'-' {
            let mut i = start + 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            self.i = i;
            return Span {
                region: Region::LineComment,
                start,
                end: i,
            };
        }
        // block comment: /* … */  (unterminated runs to the end)
        if c == b'/' {
            let mut i = start + 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            let end = if i + 1 < b.len() { i + 2 } else { b.len() };
            self.i = end;
            return Span {
                region: Region::BlockComment,
                start,
                end,
            };
        }
        // dollar-quoted body: $tag$ … $tag$  (unterminated runs to the end)
        if c == b'$' {
            let tag_end = dollar_tag_end(b, start).expect("checked by opens_special");
            let tag = &self.sql[start..=tag_end];
            let body = tag_end + 1;
            let end = match self.sql[body..].find(tag) {
                Some(close) => body + close + tag.len(),
                None => b.len(),
            };
            self.i = end;
            return Span {
                region: Region::DollarQuoted,
                start,
                end,
            };
        }
        // '…' or "…", with the doubled-quote escape and optional backslashes
        let q = c;
        let mut i = start + 1;
        while i < b.len() {
            if self.esc == BackslashEscapes::Honor && q == b'\'' && b[i] == b'\\' && i + 1 < b.len()
            {
                i += 2;
                continue;
            }
            if b[i] == q {
                // A doubled quote is an escaped quote, not a terminator.
                if i + 1 < b.len() && b[i + 1] == q {
                    i += 2;
                    continue;
                }
                i += 1;
                break;
            }
            i += 1;
        }
        let end = i.min(b.len());
        self.i = end;
        Span {
            region: Region::Quoted,
            start,
            end,
        }
    }
}

impl Iterator for Scan<'_> {
    type Item = Span;

    fn next(&mut self) -> Option<Span> {
        if self.i >= self.b.len() {
            return None;
        }
        if self.opens_special(self.i) {
            return Some(self.take_special());
        }
        // Otherwise run forward until the next non-code opener.
        let start = self.i;
        let mut i = self.i + 1;
        while i < self.b.len() && !self.opens_special(i) {
            i += 1;
        }
        self.i = i;
        Some(Span {
            region: Region::Code,
            start,
            end: i,
        })
    }
}

/// `;`-splitter aware of `'…'` / `"…"` literals, `--` and `/* */` comments, and
/// `$tag$…$tag$` dollar-quoting, so a `;` inside a function body or string never
/// ends a statement.
///
/// Used to run multi-statement batches on engines that accept only one
/// command per prepared statement, and by migration runners.
pub fn split_on_semicolons(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for span in scan(sql, BackslashEscapes::Ignore) {
        if !span.region.is_code() {
            continue;
        }
        // Only a `;` in real code ends a statement.
        for (offset, byte) in sql.as_bytes()[span.start..span.end].iter().enumerate() {
            if *byte == b';' {
                let at = span.start + offset;
                let stmt = sql[start..at].trim();
                if !stmt.is_empty() {
                    out.push(stmt.to_string());
                }
                start = at + 1;
            }
        }
    }
    let tail = sql[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// What a [`Tok`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokKind {
    /// An identifier or keyword: `[A-Za-z_][A-Za-z0-9_]*`.
    Word,
    /// An unsigned integer literal. Anything with a `.` or an exponent scans as
    /// a `Word`-adjacent run plus punctuation — we only care about plain counts.
    Num,
    /// A single punctuation byte (`(`, `)`, `,`, `;`, an operator…).
    Punct,
}

/// One lexical token of executable SQL, with the parenthesis nesting depth it
/// sits at.
///
/// `depth` is what makes this useful beyond a keyword scan: `LIMIT` at depth 0
/// bounds what the user gets back, while the same word at depth 1 bounds a
/// subquery or a CTE body and says nothing about the outer result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tok<'a> {
    pub kind: TokKind,
    pub text: &'a str,
    pub depth: u32,
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

impl Tok<'_> {
    /// ASCII-case-insensitive keyword match. `Num`/`Punct` never match a word.
    pub fn is(&self, kw: &str) -> bool {
        self.kind == TokKind::Word && self.text.eq_ignore_ascii_case(kw)
    }
    /// The token's value when it is an integer literal that fits a `u32`.
    pub fn as_u32(&self) -> Option<u32> {
        (self.kind == TokKind::Num)
            .then(|| self.text.parse().ok())
            .flatten()
    }
}

/// Tokenize the **code** regions of `sql`, skipping strings, quoted identifiers,
/// comments and dollar-quoted bodies entirely.
///
/// Because non-code spans never yield tokens, `SELECT 'limit 10' FROM t` and
/// `SELECT "limit" FROM t` produce no `LIMIT` token at all — which is the whole
/// point of building this on [`scan`] instead of matching on the raw text.
///
/// Honors backslash escapes (see [`BackslashEscapes`]): this feeds decisions
/// about what the user asked for, and a literal that swallows the rest of the
/// statement would hide a real bound.
pub fn code_tokens(sql: &str) -> Vec<Tok<'_>> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut depth: u32 = 0;
    for span in scan(sql, BackslashEscapes::Honor) {
        if !span.region.is_code() {
            continue;
        }
        let mut i = span.start;
        while i < span.end {
            let c = b[i];
            if c.is_ascii_whitespace() {
                i += 1;
                continue;
            }
            // A byte >= 0x80 is part of a multi-byte character, which in a code
            // region can only be an identifier (`café`, `naïve`, a CJK table
            // name). Taking whole characters here is also what keeps every slice
            // below on a char boundary: falling through to the punctuation arm
            // would slice `&sql[i..i + 1]` mid-character and panic.
            if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 {
                let start = i;
                while i < span.end && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] >= 0x80)
                {
                    i += 1;
                }
                out.push(Tok {
                    kind: TokKind::Word,
                    text: &sql[start..i],
                    depth,
                    start,
                    end: i,
                });
                continue;
            }
            if c.is_ascii_digit() {
                let start = i;
                while i < span.end && b[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(Tok {
                    kind: TokKind::Num,
                    text: &sql[start..i],
                    depth,
                    start,
                    end: i,
                });
                continue;
            }
            // Punctuation. A `(` is reported at the depth it opens *from*, and a
            // `)` at the depth it closes *to*, so a balanced pair brackets its
            // contents symmetrically.
            if c == b')' {
                depth = depth.saturating_sub(1);
            }
            out.push(Tok {
                kind: TokKind::Punct,
                text: &sql[i..i + 1],
                depth,
                start: i,
                end: i + 1,
            });
            if c == b'(' {
                depth += 1;
            }
            i += 1;
        }
    }
    out
}

/// Strip comments and blank out string, quoted-identifier and dollar-quoted
/// contents, so keyword classification only ever sees real SQL. Each removed
/// region collapses to a single space, which keeps the tokens either side of it
/// from fusing into one.
///
/// `esc` is the caller's, because neither reading is safe on its own and this
/// function is not told the dialect. Under [`Ignore`](BackslashEscapes::Ignore),
/// MySQL's `'\''` reads as a terminated-then-reopened string and everything after
/// it — including a trailing `DROP` — vanishes into the "literal"; under
/// [`Honor`](BackslashEscapes::Honor), a standard-conforming `'C:\'` never closes
/// and swallows the rest of the batch instead. [`crate::classify::analyze`] therefore blanks
/// both ways and keeps the stronger classification.
///
/// Bytes are copied through and reassembled at the end, so non-ASCII identifiers
/// survive intact (a per-byte `as char` cast would mojibake them).
pub fn blank_non_code(sql: &str, esc: BackslashEscapes) -> String {
    let b = sql.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    for span in scan(sql, esc) {
        if span.region.is_code() {
            out.extend_from_slice(&b[span.start..span.end]);
        } else {
            out.push(b' ');
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Statement shape (profiling)
//
// A profiler's whole job is answering "which query is costing me?", and that
// question is about a *shape*, not a string: `WHERE id = 41` and `WHERE id = 42`
// are one query someone ran twice, not two queries. Collapsing literals is what
// turns a log of executions into a ranked list of problems.
//
// Engines that keep their own statement statistics normalize the same way —
// Postgres stores a `queryid`, MySQL a `DIGEST_TEXT` — so this is also what
// lets client-side recordings line up with server-side ones.
// ---------------------------------------------------------------------------

/// Collapse a statement to its shape: literals become `?`, comments vanish, and
/// whitespace normalizes to single spaces.
///
/// Built on [`scan`] rather than a regex, which is the only way to get this
/// right: `SELECT 'user 42'` must collapse its *literal* without touching the
/// digits inside it, and `col2` is an identifier that happens to end in a digit,
/// not a number to be replaced.
///
/// Variable-length `IN` lists collapse to a single `?` so that
/// `IN (1,2)` and `IN (1,2,3)` — the same query with a different batch size —
/// rank as one statement instead of fragmenting into dozens.
pub fn normalize_statement(sql: &str) -> String {
    let b = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    // Carried across spans: a literal between `ORDER BY` and its ordinals would
    // otherwise reset the clause and start collapsing them again.
    let mut ordinals = false;

    for span in scan(sql, BackslashEscapes::Honor) {
        match span.region {
            // A literal's *contents* are the variable part; the fact that there
            // was one is the shape.
            Region::Quoted if b[span.start] == b'\'' => out.push('?'),
            Region::DollarQuoted => out.push('?'),
            // A quoted identifier ("my col") names a column and is part of the
            // shape, so it survives; only string literals collapse.
            Region::Quoted => out.push_str(&sql[span.start..span.end]),
            // Comments carry no shape, and keeping them would split one query
            // into as many statements as it has annotations.
            Region::LineComment | Region::BlockComment => out.push(' '),
            Region::Code => push_code_shape(sql, span.start, span.end, &mut out, &mut ordinals),
        }
    }

    collapse_placeholder_lists(&squeeze_whitespace(&out))
}

/// Keywords that end a `GROUP BY` / `ORDER BY` list, returning integers to being
/// ordinary values.
const ORDINAL_CLAUSE_END: [&str; 8] = [
    "LIMIT",
    "OFFSET",
    "HAVING",
    "WINDOW",
    "FETCH",
    "UNION",
    "INTERSECT",
    "EXCEPT",
];

/// Copy a code region, replacing numeric literals with `?`.
///
/// Two things are deliberately *not* replaced:
///
/// * Digits continuing an identifier — the same rule [`code_tokens`] uses — so
///   `col2`, `utf8mb4` and `t1.id` survive while `LIMIT 100` collapses.
/// * Integers inside a `GROUP BY` / `ORDER BY` list. Those are **ordinal column
///   references**, not values: `GROUP BY 1` means "the first selected column".
///   Collapsing them renders the clause as the nonsense `GROUP BY ? ORDER BY ?`,
///   and worse, merges `ORDER BY 1` with `ORDER BY 2` — genuinely different
///   queries reported as one.
///
/// `ordinals` tracks whether we're inside such a list; the caller owns it so the
/// state survives a literal splitting the code region in two.
fn push_code_shape(sql: &str, start: usize, end: usize, out: &mut String, ordinals: &mut bool) {
    let b = sql.as_bytes();
    let mut i = start;
    // The last word seen, so `BY` can be recognized as following GROUP/ORDER.
    let mut prev_word = String::new();

    while i < end {
        let c = b[i];
        // An identifier: consume it whole so any digits inside are protected.
        if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 {
            let s = i;
            while i < end && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] >= 0x80) {
                i += 1;
            }
            let word = &sql[s..i];
            let upper = word.to_ascii_uppercase();
            if upper == "BY" && (prev_word == "GROUP" || prev_word == "ORDER") {
                *ordinals = true;
            } else if ORDINAL_CLAUSE_END.contains(&upper.as_str()) {
                *ordinals = false;
            }
            prev_word = upper;
            out.push_str(word);
            continue;
        }
        if c.is_ascii_digit() {
            let s = i;
            while i < end && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            if *ordinals {
                // An ordinal position: part of the shape, not a value.
                out.push_str(&sql[s..i]);
            } else {
                // `$1` is a bind placeholder, already a shape — don't double up.
                if out.ends_with('$') {
                    out.pop();
                }
                out.push('?');
            }
            prev_word.clear();
            continue;
        }
        // A closing paren leaves any subquery's ordering behind with it.
        if c == b')' {
            *ordinals = false;
        }
        if !c.is_ascii_whitespace() && c != b',' {
            prev_word.clear();
        }
        out.push(c as char);
        i += 1;
    }
}

/// Whitespace runs → one space; trailing `;` and surrounding space removed.
fn squeeze_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            in_space = true;
            continue;
        }
        if in_space && !out.is_empty() {
            out.push(' ');
        }
        in_space = false;
        out.push(ch);
    }
    out.trim().trim_end_matches(';').trim_end().to_string()
}

/// `(?, ?, ?)` → `(?)`, so a batch's size doesn't fragment its statistics.
fn collapse_placeholder_lists(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find("(?") {
        out.push_str(&rest[..open]);
        let after = &rest[open..];
        // How far does a pure `?, ?, ?` run extend from this `(`?
        let mut i = 1; // past '('
        let bytes = after.as_bytes();
        let mut saw_comma = false;
        loop {
            if i < bytes.len() && bytes[i] == b'?' {
                i += 1;
            } else {
                break;
            }
            // Allow ", " between placeholders.
            let mut j = i;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b',' {
                saw_comma = true;
                j += 1;
                while j < bytes.len() && bytes[j] == b' ' {
                    j += 1;
                }
                i = j;
            } else {
                break;
            }
        }
        if saw_comma && i < bytes.len() && bytes[i] == b')' {
            out.push_str("(?)");
            rest = &after[i + 1..];
        } else {
            out.push_str("(?");
            rest = &after[2..];
        }
    }
    out.push_str(rest);
    out
}

/// A stable short id for a statement's shape.
///
/// Hashes the **lowercased** normalization so `select 1` and `SELECT 1` are one
/// statement — they are the same query, and a profiler that ranked them apart
/// would split a hot query's cost in half and hide it.
pub fn statement_digest(sql: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(normalize_statement(sql).to_lowercase().as_bytes());
    // 16 hex chars is ample for grouping within one database's statement set,
    // and short enough to show in a table cell.
    //
    // Written out rather than `format!("{:x}", …)`: sha2 0.11 no longer
    // implements `LowerHex` on its output. The bytes and therefore the digest
    // are unchanged from the 0.10 spelling — this must stay true, because the
    // digest is what groups a profiler's statements across versions.
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let out = h.finalize();
    let mut hex = String::with_capacity(16);
    for b in out.iter().take(8) {
        hex.push(DIGITS[(b >> 4) as usize] as char);
        hex.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(text, depth)` for each token — the two things callers actually branch on.
    fn toks(sql: &str) -> Vec<(&str, u32)> {
        code_tokens(sql)
            .into_iter()
            .map(|t| (t.text, t.depth))
            .collect()
    }

    #[test]
    fn tokens_carry_their_paren_depth() {
        assert_eq!(
            toks("SELECT (a) FROM t"),
            [
                ("SELECT", 0),
                ("(", 0),
                ("a", 1),
                (")", 0),
                ("FROM", 0),
                ("t", 0)
            ]
        );
    }

    #[test]
    fn nested_parens_accumulate_depth() {
        let d: Vec<u32> = code_tokens("f((x))").into_iter().map(|t| t.depth).collect();
        //                             f ( (  x  )  )
        assert_eq!(d, [0, 0, 1, 2, 1, 0]);
    }

    #[test]
    fn literals_and_comments_yield_no_tokens() {
        // The whole reason this is built on `scan`: text that merely looks like
        // SQL must never be read as SQL.
        assert_eq!(toks("'limit 10'"), []);
        assert_eq!(toks("-- limit 10"), []);
        assert_eq!(toks("/* limit 10 */"), []);
        assert_eq!(toks(r#""limit""#), []);
    }

    #[test]
    fn words_and_numbers_are_distinguished() {
        let t = code_tokens("LIMIT 42");
        assert_eq!(t[0].kind, TokKind::Word);
        assert!(t[0].is("limit"), "keyword matching is case-insensitive");
        assert_eq!(t[1].kind, TokKind::Num);
        assert_eq!(t[1].as_u32(), Some(42));
        assert_eq!(t[0].as_u32(), None, "a word is never a count");
    }

    #[test]
    fn an_identifier_is_not_split_on_its_digits() {
        assert_eq!(
            toks("limit_reached col2"),
            [("limit_reached", 0), ("col2", 0)]
        );
    }

    #[test]
    fn non_ascii_in_a_code_region_is_one_word() {
        // A multibyte identifier — or a smart quote pasted in from a
        // document — must not slice a character in half. Release builds are
        // `panic = "abort"`, so this would take the whole app down.
        assert_eq!(
            toks("SELECT café FROM naïve"),
            [("SELECT", 0), ("café", 0), ("FROM", 0), ("naïve", 0)]
        );
        assert_eq!(
            toks("SELECT 1 — 2"),
            [("SELECT", 0), ("1", 0), ("—", 0), ("2", 0)]
        );
    }

    #[test]
    fn depth_never_underflows_on_unbalanced_input() {
        // Half-typed SQL reaches this on every keystroke; it must not panic.
        let d: Vec<u32> = code_tokens(")))a").into_iter().map(|t| t.depth).collect();
        assert_eq!(d, [0, 0, 0, 0]);
    }

    #[test]
    fn code_only_input_is_one_span() {
        let spans: Vec<_> = scan("SELECT 1", BackslashEscapes::Ignore).collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].region, Region::Code);
    }

    #[test]
    fn regions_are_tagged() {
        let sql = "SELECT 'a', /* c */ x -- t\nFROM $$b$$";
        let kinds: Vec<_> = scan(sql, BackslashEscapes::Ignore)
            .map(|s| s.region)
            .filter(|r| !r.is_code())
            .collect();
        assert_eq!(
            kinds,
            vec![
                Region::Quoted,
                Region::BlockComment,
                Region::LineComment,
                Region::DollarQuoted
            ]
        );
    }

    #[test]
    fn a_lone_dollar_is_code() {
        // `$1` is a bind placeholder, not a dollar-quote opener.
        let spans: Vec<_> = scan("SELECT $1", BackslashEscapes::Ignore).collect();
        assert!(spans.iter().all(|s| s.region.is_code()));
    }

    #[test]
    fn semicolons_inside_literals_do_not_split() {
        assert_eq!(split_on_semicolons("SELECT 'a;b'"), vec!["SELECT 'a;b'"]);
        assert_eq!(
            split_on_semicolons("SELECT \"a;b\""),
            vec!["SELECT \"a;b\""]
        );
        assert_eq!(
            split_on_semicolons("SELECT 1 -- a;b"),
            vec!["SELECT 1 -- a;b"]
        );
        assert_eq!(
            split_on_semicolons("SELECT /* a;b */ 1"),
            vec!["SELECT /* a;b */ 1"]
        );
    }

    #[test]
    fn dollar_body_stays_one_statement() {
        let sql = "CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END; $$ LANGUAGE plpgsql; SELECT 2";
        let out = split_on_semicolons(sql);
        assert_eq!(out.len(), 2, "got {out:?}");
        assert!(out[0].starts_with("CREATE FUNCTION"));
        assert_eq!(out[1], "SELECT 2");
    }

    #[test]
    fn empty_statements_are_dropped() {
        assert_eq!(
            split_on_semicolons("SELECT 1;;; SELECT 2;"),
            vec!["SELECT 1", "SELECT 2"]
        );
        assert!(split_on_semicolons("   ;  ; ").is_empty());
    }

    #[test]
    fn blanking_removes_literals_and_comments() {
        // Asserted on content rather than exact spacing: how many spaces a
        // removed region collapses to is an implementation detail, but the
        // keyword disappearing and the surrounding code surviving are not.
        let out = blank_non_code("SELECT 'DROP' -- x\n, 1", BackslashEscapes::Honor);
        assert!(!out.contains("DROP"), "literal leaked: {out:?}");
        assert!(!out.contains('x'), "comment leaked: {out:?}");
        assert!(
            out.starts_with("SELECT") && out.contains(", 1"),
            "code lost: {out:?}"
        );

        assert!(
            !blank_non_code("SELECT $$ DROP TABLE t $$", BackslashEscapes::Honor).contains("DROP")
        );
        assert!(!blank_non_code("SELECT \"DROP\"", BackslashEscapes::Honor).contains("DROP"));
    }

    #[test]
    fn blanking_separates_tokens_it_removes() {
        // The space matters: without it `a'x'b` would classify as one token.
        assert_eq!(blank_non_code("a'x'b", BackslashEscapes::Honor), "a b");
    }

    #[test]
    fn non_ascii_survives_blanking() {
        assert_eq!(
            blank_non_code("SELECT café FROM naïve", BackslashEscapes::Honor),
            "SELECT café FROM naïve"
        );
    }

    #[test]
    fn backslash_handling_differs_by_caller() {
        // MySQL-style: '\'' is a one-char string, so the DROP stays visible.
        let mysql = r"SELECT '\'' ; DROP TABLE users";
        assert!(blank_non_code(mysql, BackslashEscapes::Honor).contains("DROP"));

        // Read the other way, the same input hides it — which is why the safety
        // classifier asks for both readings rather than picking one.
        assert!(!blank_non_code(mysql, BackslashEscapes::Ignore).contains("DROP"));

        // The splitter takes the opposite choice on purpose, so a standard-
        // conforming `'a\'` closes where Postgres closes it and the following
        // statement is still seen. Locking both behaviors down here means a
        // future "simplification" to one shared setting fails loudly.
        let pg = r"SELECT 'a\'; DROP TABLE t";
        assert_eq!(split_on_semicolons(pg).len(), 2);
    }

    #[test]
    fn unterminated_constructs_terminate() {
        // Half-typed SQL must not hang or panic.
        assert_eq!(split_on_semicolons("SELECT 'oops"), vec!["SELECT 'oops"]);
        assert_eq!(split_on_semicolons("SELECT $$oops"), vec!["SELECT $$oops"]);
        assert_eq!(split_on_semicolons("SELECT /*oops"), vec!["SELECT /*oops"]);
        assert!(!blank_non_code("SELECT 'oops", BackslashEscapes::Honor).is_empty());
    }

    // ---- statement shape ---------------------------------------------------

    #[test]
    fn literals_collapse_to_placeholders() {
        assert_eq!(
            normalize_statement("SELECT * FROM orders WHERE id = 42 AND name = 'bob'"),
            "SELECT * FROM orders WHERE id = ? AND name = ?"
        );
    }

    #[test]
    fn the_same_query_with_different_values_is_one_shape() {
        // The entire point: these must rank as one statement run twice.
        assert_eq!(
            normalize_statement("DELETE FROM t WHERE id = 41"),
            normalize_statement("DELETE FROM t WHERE id = 42")
        );
        assert_eq!(
            statement_digest("DELETE FROM t WHERE id = 41"),
            statement_digest("DELETE FROM t WHERE id = 42")
        );
    }

    #[test]
    fn digits_inside_identifiers_are_not_literals() {
        // `col2` is a column; `utf8mb4` a charset. Replacing their digits would
        // merge genuinely different queries.
        assert_eq!(
            normalize_statement("SELECT col2, t1.id FROM utf8mb4_tbl t1 LIMIT 100"),
            "SELECT col2, t1.id FROM utf8mb4_tbl t1 LIMIT ?"
        );
    }

    #[test]
    fn digits_inside_a_literal_are_not_touched_separately() {
        // The literal collapses as a unit — no `?` leaking out of its digits.
        assert_eq!(
            normalize_statement("SELECT * FROM t WHERE note = 'user 42 said hi'"),
            "SELECT * FROM t WHERE note = ?"
        );
    }

    #[test]
    fn quoted_identifiers_survive_but_strings_do_not() {
        // `"my col"` names a column — part of the shape. `'x'` is a value.
        assert_eq!(
            normalize_statement("SELECT \"my col\" FROM t WHERE a = 'x'"),
            "SELECT \"my col\" FROM t WHERE a = ?"
        );
    }

    #[test]
    fn in_lists_of_different_lengths_are_one_shape() {
        // Otherwise a batched query fragments into one entry per batch size and
        // never surfaces, however much time it costs in total.
        let two = normalize_statement("SELECT * FROM t WHERE id IN (1, 2)");
        let five = normalize_statement("SELECT * FROM t WHERE id IN (1,2,3,4,5)");
        assert_eq!(two, "SELECT * FROM t WHERE id IN (?)");
        assert_eq!(two, five);
    }

    #[test]
    fn a_single_element_list_keeps_its_shape() {
        assert_eq!(
            normalize_statement("SELECT * FROM t WHERE id IN (1)"),
            "SELECT * FROM t WHERE id IN (?)"
        );
    }

    #[test]
    fn a_function_call_is_not_mistaken_for_a_placeholder_list() {
        assert_eq!(
            normalize_statement("SELECT coalesce(a, b) FROM t"),
            "SELECT coalesce(a, b) FROM t"
        );
    }

    #[test]
    fn comments_and_whitespace_do_not_split_a_statement() {
        let a = "SELECT a\n  FROM t   -- nightly job\n WHERE x = 1";
        let b = "/* other note */ SELECT a FROM t WHERE x = 2";
        assert_eq!(statement_digest(a), statement_digest(b));
    }

    #[test]
    fn case_does_not_split_a_statement() {
        assert_eq!(statement_digest("select 1"), statement_digest("SELECT 1"));
    }

    #[test]
    fn ordinal_positions_are_shape_not_value() {
        // `GROUP BY 1` means "the first selected column". Collapsing it renders
        // the nonsense `GROUP BY ?` — and merges two different queries.
        assert_eq!(
            normalize_statement("SELECT a, count(*) FROM t GROUP BY 1 ORDER BY 2 DESC LIMIT 5"),
            "SELECT a, count(*) FROM t GROUP BY 1 ORDER BY 2 DESC LIMIT ?"
        );
    }

    #[test]
    fn different_orderings_stay_different_statements() {
        assert_ne!(
            statement_digest("SELECT a, b FROM t ORDER BY 1"),
            statement_digest("SELECT a, b FROM t ORDER BY 2")
        );
    }

    #[test]
    fn every_ordinal_in_a_list_survives() {
        assert_eq!(
            normalize_statement("SELECT a, b FROM t GROUP BY 1, 2 ORDER BY 2, 1"),
            "SELECT a, b FROM t GROUP BY 1, 2 ORDER BY 2, 1"
        );
    }

    #[test]
    fn values_after_an_ordinal_clause_still_collapse() {
        // The clause ends at LIMIT/OFFSET/HAVING; integers are values again.
        assert_eq!(
            normalize_statement("SELECT a FROM t GROUP BY 1 HAVING count(*) > 10 LIMIT 20"),
            "SELECT a FROM t GROUP BY 1 HAVING count(*) > ? LIMIT ?"
        );
    }

    #[test]
    fn an_ordinal_clause_does_not_leak_out_of_a_subquery() {
        assert_eq!(
            normalize_statement("SELECT * FROM (SELECT a FROM t ORDER BY 1) s WHERE s.a = 99"),
            "SELECT * FROM (SELECT a FROM t ORDER BY 1) s WHERE s.a = ?"
        );
    }

    #[test]
    fn ordering_by_a_column_name_is_unaffected() {
        assert_eq!(
            normalize_statement("SELECT * FROM t ORDER BY created_at DESC LIMIT 10"),
            "SELECT * FROM t ORDER BY created_at DESC LIMIT ?"
        );
    }

    #[test]
    fn bind_placeholders_stay_single() {
        // `$1` is already a shape; it must not become `$?`.
        assert_eq!(
            normalize_statement("SELECT * FROM t WHERE id = $1"),
            "SELECT * FROM t WHERE id = ?"
        );
    }

    #[test]
    fn trailing_semicolons_and_padding_do_not_split_a_statement() {
        assert_eq!(
            statement_digest("  SELECT 1 ;  "),
            statement_digest("SELECT 1")
        );
    }

    #[test]
    fn different_queries_stay_different() {
        assert_ne!(
            statement_digest("SELECT * FROM orders"),
            statement_digest("SELECT * FROM customers")
        );
    }

    #[test]
    fn unterminated_input_still_normalizes() {
        // Half-typed SQL reaches the recorder too; it must not panic.
        assert!(!normalize_statement("SELECT 'oops").is_empty());
        assert!(!statement_digest("SELECT /*oops").is_empty());
        assert_eq!(normalize_statement(""), "");
    }
}
