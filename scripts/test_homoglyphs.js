import assert from "node:assert/strict";
import { loadData } from "../lib/data.js";
import { scoreDomain } from "../lib/scoring.js";
import { decodeIdn, unicodeSkeleton, isMixedScript, asciiHomoglyphs } from "../lib/domain/confusables.js";

// 1. Unicode TR39 skeleton tests
assert.equal(unicodeSkeleton("dаs.com"), "das.com", "Cyrillic a normalises to Latin a");
assert.equal(unicodeSkeleton("oсbc.com"), "ocbc.com", "Cyrillic c normalises to Latin c");
assert.equal(unicodeSkeleton("singpаss.com"), "singpass.com", "Cyrillic a normalises in singpass");
assert.equal(unicodeSkeleton("pоsb.com"), "posb.com", "Cyrillic o normalises in posb");
assert.equal(unicodeSkeleton("uоb.com.sg"), "uob.com.sg", "Cyrillic o normalises in uob");
assert.equal(unicodeSkeleton("cрf.com"), "cpf.com", "Cyrillic r normalises to Latin p");
assert.equal(unicodeSkeleton("ıcp.com"), "icp.com", "Dotless i normalises to Latin i");
assert.equal(unicodeSkeleton("sngpøsnt.com"), "sngposnt.com", "Slashed o normalises to Latin o");

// 2. Mixed script detection tests
assert.equal(isMixedScript("dаs"), true, "dаs contains Latin and Cyrillic");
assert.equal(isMixedScript("oсbc"), true, "oсbc contains Latin and Cyrillic");
assert.equal(isMixedScript("dbs"), false, "Pure Latin is not mixed script");
assert.equal(isMixedScript("com"), false, "Pure Latin TLD is not mixed script");

// 3. Punycode IDN decoding tests
const idn1 = decodeIdn("xn--dbs-9ka.com");
assert.equal(idn1.isPunycode, true, "xn-- is recognised as Punycode");
assert.equal(idn1.skeleton, "dabs.com", "Punycode decodes and skeletonises to dabs.com");

const idn2 = decodeIdn("xn--0cbc-1ra.com");
assert.equal(idn2.isPunycode, true, "xn--0cbc is recognised as Punycode");

// 4. ASCII homoglyph / Leetspeak tests
assert.ok(asciiHomoglyphs("0cbc").includes("ocbc"), "0cbc transforms to ocbc");
assert.ok(asciiHomoglyphs("singpa55").includes("singpass"), "singpa55 transforms to singpass");
assert.ok(asciiHomoglyphs("u0b").includes("uob"), "u0b transforms to uob");
assert.ok(asciiHomoglyphs("p0sb").includes("posb"), "p0sb transforms to posb");
assert.ok(asciiHomoglyphs("rnaybank").includes("maybank"), "rnaybank transforms to maybank");
assert.ok(asciiHomoglyphs("1ras-tax").includes("iras-tax"), "1ras-tax transforms to iras-tax");

// 5. End-to-end scoring integration tests
const data = loadData();

const resOcbcCyrillic = scoreDomain("oсbc.com", data);
assert.ok(resOcbcCyrillic.score >= 70, "oсbc.com must score >= alert_min (70)");
assert.ok(resOcbcCyrillic.signals.some((s) => s.type === "mixed_script_label"), "oсbc.com fires mixed_script_label");
assert.ok(resOcbcCyrillic.signals.some((s) => s.type === "confusable_skeleton_match"), "oсbc.com fires confusable_skeleton_match");

const resSingpassCyrillic = scoreDomain("singpаss.com", data);
assert.ok(resSingpassCyrillic.score >= 70, "singpаss.com must score >= alert_min (70)");
assert.ok(resSingpassCyrillic.signals.some((s) => s.type === "mixed_script_label"), "singpаss.com fires mixed_script_label");

const resP0sb = scoreDomain("p0sb.com", data);
assert.ok(resP0sb.score >= 70, "p0sb.com must score >= alert_min (70)");
assert.ok(resP0sb.signals.some((s) => s.type === "homoglyph:ascii"), "p0sb.com fires homoglyph:ascii");

const resRnaybank = scoreDomain("rnaybank.com", data);
assert.ok(resRnaybank.score >= 70, "rnaybank.com must score >= alert_min (70)");
assert.ok(resRnaybank.signals.some((s) => s.type === "homoglyph:ascii"), "rnaybank.com fires homoglyph:ascii");

const resSingpa55 = scoreDomain("singpa55.com", data);
assert.ok(resSingpa55.score >= 70, "singpa55.com must score >= alert_min (70)");
assert.ok(resSingpa55.signals.some((s) => s.type === "homoglyph:ascii"), "singpa55.com fires homoglyph:ascii");

console.log("Homoglyph and confusable tests passed.");
