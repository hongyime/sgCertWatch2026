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
    const affixKeywords = (keywords?.keywords || [])
      .filter((k) => k.affix)
      .map((k) => String(k.token || "").toLowerCase().replace(/[^a-z0-9]/g, ""));

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
