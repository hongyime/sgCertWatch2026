import allowlist from "../allowlist.json" with { type: "json" };
import keywords from "../keywords.json" with { type: "json" };
import schemes from "../schemes.json" with { type: "json" };
import watchlist from "../watchlist.json" with { type: "json" };

let cachedData;

function loadData() {
  if (!cachedData) {
    cachedData = {
      watchlist,
      keywords,
      allowlist,
      schemes
    };
  }
  return cachedData;
}

export { loadData };
