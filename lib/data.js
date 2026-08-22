import allowlist from "../allowlist.json" with { type: "json" };
import keywords from "../keywords.json" with { type: "json" };
import schemes from "../schemes.json" with { type: "json" };
import watchlist from "../watchlist.json" with { type: "json" };
import scoring from "../scoring.json" with { type: "json" };

let cachedData;

function loadData() {
  if (!cachedData) {
    cachedData = {
      watchlist,
      keywords,
      allowlist,
      schemes,
      scoring
    };
  }
  return cachedData;
}

export { loadData };
