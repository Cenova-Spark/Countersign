/**
 * RFC 8785 (JSON Canonicalization Scheme), restricted to integers.
 *
 * A direct port of `countersign-verify`'s `jcs.rs`. Canonicalization is where
 * two implementations disagree silently and a valid approval fails to verify,
 * so this is written out rather than depended on, and checked against the same
 * committed vectors the Rust one is.
 *
 * Two things are easier here than in Rust, and one is harder.
 *
 * **Easier:** JavaScript strings are already UTF-16, so the default `sort()`
 * comparison is UTF-16 code-unit order — exactly what RFC 8785 requires. In
 * Rust that had to be written out, because `str: Ord` compares UTF-8 bytes and
 * the two disagree above the BMP.
 *
 * **Also easier:** `Number.isInteger` and `Number.MAX_SAFE_INTEGER` are the
 * spec's own vocabulary for the restriction this profile applies.
 *
 * **Harder:** `JSON.parse` collapses duplicate keys silently, so detecting them
 * needs a separate scan of the source text. See {@link findDuplicateKey}.
 */

/** The largest integer every JSON implementation agrees about: 2^53 - 1. */
const SAFE_INT_MAX = Number.MAX_SAFE_INTEGER;

export type JcsErrorKind = "unsupported_number" | "duplicate_key" | "malformed";

export class JcsError extends Error {
  readonly kind: JcsErrorKind;

  constructor(message: string, kind: JcsErrorKind) {
    super(message);
    this.name = "JcsError";
    this.kind = kind;
  }
}

/**
 * Canonicalize an already-parsed value.
 *
 * Duplicate keys cannot be detected here — the parse has already collapsed
 * them. Use {@link canonicalizeText} for input from somewhere you do not
 * control.
 */
export function canonicalize(value: unknown): string {
  const out: string[] = [];
  writeValue(value, out);
  return out.join("");
}

/** Canonicalize JSON text, rejecting duplicate object keys. */
export function canonicalizeText(json: string): string {
  const duplicate = findDuplicateKey(json);
  if (duplicate !== null) {
    throw new JcsError(`duplicate object key ${JSON.stringify(duplicate)}`, "duplicate_key");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new JcsError(`malformed JSON: ${(e as Error).message}`, "malformed");
  }
  return canonicalize(parsed);
}

function writeValue(value: unknown, out: string[]): void {
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "number":
      writeNumber(value, out);
      return;
    case "string":
      out.push(writeString(value));
      return;
    case "object":
      break;
    default:
      throw new JcsError(`cannot canonicalize a ${typeof value}`, "malformed");
  }

  if (Array.isArray(value)) {
    out.push("[");
    value.forEach((item, index) => {
      if (index > 0) out.push(",");
      writeValue(item, out);
    });
    out.push("]");
    return;
  }

  // Sorted by UTF-16 code unit, which is what the default comparison already
  // does — JavaScript strings are UTF-16. This is the rule that has to be
  // written out by hand in languages whose strings are not.
  const keys = Object.keys(value as Record<string, unknown>).sort();
  out.push("{");
  keys.forEach((key, index) => {
    if (index > 0) out.push(",");
    out.push(writeString(key));
    out.push(":");
    writeValue((value as Record<string, unknown>)[key], out);
  });
  out.push("}");
}

function writeNumber(value: number, out: string[]): void {
  if (!Number.isInteger(value) || Math.abs(value) > SAFE_INT_MAX) {
    throw new JcsError(
      `number ${value} is not an integer within ±(2^53-1); Countersign v1 canonicalizes ` +
        `integers only`,
      "unsupported_number",
    );
  }
  // `-0` would serialize as "0" via String(), which is what we want, but be
  // explicit rather than relying on it.
  out.push(String(value === 0 ? 0 : value));
}

/**
 * RFC 8785 escaping: only `"`, `\` and C0 controls, the five short forms where
 * they exist, `\u00xx` with lowercase hex otherwise. `/` is not escaped, and
 * non-ASCII travels as UTF-8.
 */
function writeString(value: string): string {
  let out = '"';
  for (const char of value) {
    switch (char) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\t":
        out += "\\t";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\r":
        out += "\\r";
        break;
      default: {
        const code = char.codePointAt(0)!;
        if (code < 0x20) {
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += char;
        }
      }
    }
  }
  return out + '"';
}

/**
 * Find the first duplicate object key in JSON text, or `null`.
 *
 * `JSON.parse` keeps the last of a duplicate pair and says nothing, so two
 * parsers can disagree about which of `{"ttl_ms":1,"ttl_ms":999999}` wins and
 * produce different digests for the same bytes — with the disagreement chosen
 * by whoever sent them. RFC 8785 requires rejection, so this scans the source.
 *
 * It is a scanner, not a parser: it tracks nesting and string state well enough
 * to know which tokens are keys, and leaves every other judgement to
 * `JSON.parse`.
 */
export function findDuplicateKey(json: string): string | null {
  const scopes: Array<Set<string> | null> = []; // null marks an array scope
  let i = 0;
  let expectKey = false;

  while (i < json.length) {
    const char = json[i];

    if (char === '"') {
      const [text, next] = readString(json, i);
      i = next;
      if (expectKey && scopes.length > 0) {
        const scope = scopes[scopes.length - 1];
        if (scope !== null) {
          if (scope.has(text)) return text;
          scope.add(text);
        }
        expectKey = false;
      }
      continue;
    }

    switch (char) {
      case "{":
        scopes.push(new Set());
        expectKey = true;
        break;
      case "[":
        scopes.push(null);
        expectKey = false;
        break;
      case "}":
      case "]":
        scopes.pop();
        expectKey = false;
        break;
      case ",":
        // A comma inside an object introduces the next key.
        expectKey = scopes.length > 0 && scopes[scopes.length - 1] !== null;
        break;
      default:
        break;
    }
    i += 1;
  }
  return null;
}

/** Read a JSON string starting at `start`, returning its value and end index. */
function readString(json: string, start: number): [string, number] {
  let i = start + 1;
  let raw = '"';
  while (i < json.length) {
    const char = json[i];
    raw += char;
    if (char === "\\") {
      // Skip the escaped character so an escaped quote does not end the string.
      raw += json[i + 1] ?? "";
      i += 2;
      continue;
    }
    i += 1;
    if (char === '"') break;
  }
  let text: string;
  try {
    text = JSON.parse(raw) as string;
  } catch {
    // Malformed; let JSON.parse report it properly later.
    text = raw;
  }
  return [text, i];
}
