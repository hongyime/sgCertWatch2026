import { domainToUnicode } from "node:url";

// Unicode TR39 confusable mapping table (Cyrillic, Greek, fullwidth, Latin variants)
const TR39_MAP = new Map([
  // Cyrillic small & capital
  ["а", "a"], ["А", "a"],
  ["б", "b"], ["Б", "b"],
  ["в", "v"], ["В", "b"],
  ["г", "g"], ["Г", "r"],
  ["д", "d"], ["Д", "d"], ["ԁ", "d"], ["Ԃ", "d"],
  ["е", "e"], ["Е", "e"], ["ѐ", "e"], ["ё", "e"],
  ["ж", "zh"], ["Ж", "zh"],
  ["з", "z"], ["З", "z"],
  ["и", "u"], ["И", "u"], ["і", "i"], ["І", "i"], ["ї", "i"], ["Ї", "i"],
  ["й", "i"], ["Й", "i"],
  ["ј", "j"], ["Ј", "j"],
  ["к", "k"], ["К", "k"],
  ["л", "l"], ["Л", "l"],
  ["м", "m"], ["М", "m"],
  ["н", "h"], ["Н", "h"],
  ["о", "o"], ["О", "o"],
  ["п", "n"], ["П", "n"],
  ["р", "p"], ["Р", "p"],
  ["с", "c"], ["С", "c"],
  ["т", "t"], ["Т", "t"],
  ["у", "y"], ["У", "y"],
  ["ф", "f"], ["Ф", "f"],
  ["х", "x"], ["Х", "x"],
  ["ц", "ts"], ["Ц", "ts"],
  ["ч", "ch"], ["Ч", "ch"],
  ["ш", "sh"], ["Ш", "sh"],
  ["щ", "shch"], ["Щ", "shch"],
  ["ъ", ""], ["Ъ", ""],
  ["ы", "bl"], ["Ы", "bl"],
  ["ь", ""], ["Ь", "b"],
  ["э", "e"], ["Э", "e"],
  ["ю", "yu"], ["Ю", "yu"],
  ["я", "ya"], ["Я", "ya"],
  ["ѕ", "s"], ["Ѕ", "s"],

  // Greek small & capital
  ["α", "a"], ["Α", "a"],
  ["β", "b"], ["Β", "b"],
  ["γ", "y"], ["Γ", "r"],
  ["δ", "d"], ["Δ", "d"],
  ["ε", "e"], ["Ε", "e"],
  ["ζ", "z"], ["Ζ", "z"],
  ["η", "n"], ["Η", "h"],
  ["θ", "th"], ["Θ", "th"],
  ["ι", "i"], ["Ι", "i"],
  ["κ", "k"], ["Κ", "k"],
  ["λ", "l"], ["Λ", "l"],
  ["μ", "m"], ["Μ", "m"],
  ["ν", "v"], ["Ν", "n"],
  ["ξ", "x"], ["Ξ", "x"],
  ["ο", "o"], ["Ο", "o"],
  ["π", "n"], ["Π", "n"],
  ["ρ", "p"], ["Р", "p"],
  ["σ", "o"], ["ς", "s"], ["Σ", "e"],
  ["τ", "t"], ["Τ", "t"],
  ["υ", "u"], ["Υ", "y"],
  ["φ", "f"], ["Φ", "f"],
  ["χ", "x"], ["Χ", "x"],
  ["ψ", "ps"], ["Ψ", "ps"],
  ["ω", "w"], ["Ω", "o"],

  // Latin extended variants & ligatures
  ["ı", "i"], ["İ", "i"],
  ["ø", "o"], ["Ø", "o"],
  ["æ", "ae"], ["Æ", "ae"],
  ["œ", "oe"], ["Œ", "oe"],
  ["ð", "d"], ["Ð", "d"],
  ["þ", "th"], ["Þ", "th"],
  ["ß", "ss"],
  ["ł", "l"], ["Ł", "l"],
  ["đ", "d"], ["Đ", "d"]
]);

/**
 * Normalise a Unicode string to its TR39 ASCII confusable prototype skeleton.
 */
export function unicodeSkeleton(input) {
  if (!input || typeof input !== "string") return "";
  const decomposed = input.normalize("NFKD");
  let out = "";
  for (const ch of decomposed) {
    if (ch >= "\u0300" && ch <= "\u036F") continue;
    if (ch >= "\u1AB0" && ch <= "\u1AFF") continue;
    if (ch >= "\u1DC0" && ch <= "\u1DFF") continue;
    if (ch >= "\u20D0" && ch <= "\u20FF") continue;
    if (ch >= "\uFE20" && ch <= "\uFE2F") continue;

    const lower = ch.toLowerCase();
    if (TR39_MAP.has(ch)) {
      out += TR39_MAP.get(ch);
    } else if (TR39_MAP.has(lower)) {
      out += TR39_MAP.get(lower);
    } else {
      out += lower;
    }
  }
  return out;
}

/**
 * Check if a string contains characters from multiple distinct scripts (Latin, Cyrillic, Greek).
 */
export function isMixedScript(input) {
  if (!input || typeof input !== "string") return false;
  let hasLatin = false;
  let hasCyrillic = false;
  let hasGreek = false;

  for (const ch of input) {
    const code = ch.codePointAt(0);
    if ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
      hasLatin = true;
    } else if ((code >= 0x0400 && code <= 0x04FF) || (code >= 0x0500 && code <= 0x052F)) {
      hasCyrillic = true;
    } else if ((code >= 0x0370 && code <= 0x03FF) || (code >= 0x1F00 && code <= 0x1FFF)) {
      hasGreek = true;
    }
  }

  const scriptCount = (hasLatin ? 1 : 0) + (hasCyrillic ? 1 : 0) + (hasGreek ? 1 : 0);
  return scriptCount >= 2;
}

/**
 * Decode Punycode IDN domain name into Unicode and skeleton forms.
 */
export function decodeIdn(domain) {
  if (!domain || typeof domain !== "string") {
    return { unicode: "", skeleton: "", isPunycode: false, hasMixedScript: false };
  }
  const isPunycode = domain.toLowerCase().includes("xn--");
  let unicode = domain;
  try {
    unicode = domainToUnicode(domain);
  } catch (_err) {
    unicode = domain;
  }

  const skeleton = unicodeSkeleton(unicode);
  const labels = unicode.split(".");
  const hasMixedScript = labels.some((label) => isMixedScript(label));

  return {
    unicode,
    skeleton,
    isPunycode,
    hasMixedScript
  };
}

/**
 * Generate ASCII homoglyph / leetspeak transformation candidates for a label.
 * Maps common leetspeak substitutions:
 * 0 -> o, 1 -> i, 5 -> s, 8 -> b, 3 -> e, 4 -> a, rn -> m, vv -> w, cl -> d
 */
export function asciiHomoglyphs(label) {
  if (!label || typeof label !== "string") return [];
  const s = label.toLowerCase();
  const candidates = new Set();

  let transformed = s
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/cl/g, "d");

  const leetSub = transformed
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/5/g, "s")
    .replace(/8/g, "b")
    .replace(/3/g, "e")
    .replace(/4/g, "a");

  if (leetSub !== s) candidates.add(leetSub);

  const leetSubL = transformed
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/5/g, "s")
    .replace(/8/g, "b")
    .replace(/3/g, "e")
    .replace(/4/g, "a");

  if (leetSubL !== s) candidates.add(leetSubL);

  return [...candidates];
}
