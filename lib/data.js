import allowlist from "../allowlist.json" with { type: "json" };
import keywords from "../keywords.json" with { type: "json" };
import schemes from "../schemes.json" with { type: "json" };
import watchlist from "../watchlist.json" with { type: "json" };
import scoring from "../scoring.json" with { type: "json" };
import wordlistData from "../common_words.json" with { type: "json" };

let cachedData;

function loadData() {
  if (!cachedData) {
    const allowlistByBrand = {};
    const allowlistSet = new Set();
    for (const e of allowlist.entries || []) {
      if (e.verified && e.registrable) {
        allowlistSet.add(e.registrable);
        if (!allowlistByBrand[e.brand]) allowlistByBrand[e.brand] = [];
        allowlistByBrand[e.brand].push(e.registrable);
      }
    }
    const compact = (s) => String(s || "").trim().toLowerCase().replace(/[^a-z0-9]/g, "");

    function getCharMask(str) {
      let l = 0;
      let d = 0;
      for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        if (c >= 97 && c <= 122) l |= (1 << (c - 97));
        else if (c >= 48 && c <= 57) d |= (1 << (c - 48));
      }
      return { l, d };
    }

    function popcount32(x) {
      x = x - ((x >> 1) & 0x55555555);
      x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
      return (((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
    }

    for (const b of watchlist?.brands || []) {
      b._compactTokens = (b.tokens || []).map(compact);
      b._compactContextTokens = (b.context_tokens || []).map(compact);
      b._tokenMasks = b._compactTokens.map(getCharMask);
      b._tokenUniques = b._tokenMasks.map((m) => popcount32(m.l) + popcount32(m.d));
    }

    // G-1/G-2: Word-collision detection. For each brand token, check whether any
    // word in common_words.json lies within the token's configured edit distance.
    // Colliding tokens are force-exact (effectiveMaxDist=0) in scoring to prevent
    // fuzzy alerts against common English words. Tokens that ARE themselves in the
    // wordlist also require a context-token presence check for exact matching.
    const wordSet = new Set((wordlistData.words || []).map(compact));

    function simpleLD(a, b, maxD) {
      if (Math.abs(a.length - b.length) > maxD) return maxD + 1;
      if (a === b) return 0;
      const la = a.length, lb = b.length;
      const prev = Array.from({ length: lb + 1 }, (_, i) => i);
      const curr = new Array(lb + 1);
      for (let i = 1; i <= la; i++) {
        curr[0] = i;
        for (let j = 1; j <= lb; j++) {
          const cost = a[j - 1] === b[j - 1] ? 0 : 1;
          curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
        }
        prev.splice(0, prev.length, ...curr);
      }
      return prev[lb];
    }

    for (const b of watchlist?.brands || []) {
      const forcedExact = new Set();  // compactToken → force exact-only matching
      const exactRequiresCtx = new Set();  // compactToken → require context even for exact
      const maxEd = b.max_edit_distance ?? 1;
      for (const tok of b._compactTokens || []) {
        if (wordSet.has(tok)) {
          exactRequiresCtx.add(tok);
          forcedExact.add(tok);
        }
        if (maxEd > 0) {
          for (const word of wordSet) {
            if (word === tok) continue;
            if (Math.abs(word.length - tok.length) > maxEd) continue;
            if (simpleLD(word, tok, maxEd) <= maxEd) {
              forcedExact.add(tok);
              break;
            }
          }
        }
      }
      b._forcedExactTokens = forcedExact;
      b._exactRequiresCtxTokens = exactRequiresCtx;
    }

    for (const k of keywords?.keywords || []) {
      k._compactToken = compact(k.token);
    }

    for (const s of schemes?.schemes || []) {
      s._compactTokens = (s.tokens || []).map(compact);
    }

    const affixKeywords = (keywords?.keywords || [])
      .filter((k) => k.affix)
      .map((k) => compact(k.token));

    cachedData = {
      watchlist,
      keywords,
      allowlist,
      schemes,
      scoring,
      allowlistSet,
      allowlistByBrand,
      affixKeywords
    };
  }
  return cachedData;
}

export { loadData };
