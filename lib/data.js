import fs from "node:fs";

let cachedData;

function readJson(name) {
  return JSON.parse(fs.readFileSync(new URL(`../${name}`, import.meta.url), "utf8"));
}

function loadData() {
  if (!cachedData) {
    cachedData = {
      watchlist: readJson("watchlist.json"),
      keywords: readJson("keywords.json"),
      allowlist: readJson("allowlist.json"),
      schemes: readJson("schemes.json")
    };
  }
  return cachedData;
}

export { loadData };
