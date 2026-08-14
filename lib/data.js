import fs from "node:fs";
import path from "node:path";

let cachedData;

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(process.cwd(), name), "utf8"));
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
