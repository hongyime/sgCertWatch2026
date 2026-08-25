// Defanging: render potentially-hostile URLs and domains inert in text output so
// analysts and non-technical readers cannot accidentally activate them.

export function defangHost(host) {
  return String(host || "").replace(/\./g, "[.]");
}

export function defangUrl(url) {
  return String(url || "")
    .replace(/^https:\/\//i, "hXXps://")
    .replace(/^http:\/\//i, "hXXp://")
    .replace(/\./g, "[.]");
}
