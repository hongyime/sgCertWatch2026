import allowlist from "../allowlist.json" with { type: "json" };
import keywords from "../keywords.json" with { type: "json" };
import schemes from "../schemes.json" with { type: "json" };
import watchlist from "../watchlist.json" with { type: "json" };
import scoring from "../scoring.json" with { type: "json" };

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
