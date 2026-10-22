import { describe, expect, it } from "vitest";
import { formatBytes, humanize, isOverdue, safeUrl } from "@/lib/utils";
import { qs } from "@/lib/api";
import { REL_RULES, STATE_HELP, STATE_LABEL } from "@/lib/labels";

describe("safeUrl", () => {
  it("allows only http(s) links from untrusted sources", () => {
    expect(safeUrl("https://nvd.nist.gov/vuln/detail/CVE-2025-1")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2025-1");
    expect(safeUrl("http://example.com/a")).toBe("http://example.com/a");
    for (const bad of ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>1</script>", "file:///etc/passwd", "ftp://x.test", "//evil.test", "not a url", "", null, undefined]) {
      expect(safeUrl(bad as any)).toBeNull();
    }
  });
});

describe("formatting helpers", () => {
  it("humanizes enum values", () => {
    expect(humanize("potential_impact")).toBe("Potential impact");
    expect(humanize(null)).toBe("—");
  });
  it("formats sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
  it("detects overdue dates", () => {
    expect(isOverdue("2000-01-01")).toBe(true);
    expect(isOverdue("2999-01-01")).toBe(false);
    expect(isOverdue(null)).toBe(false);
  });
  it("builds query strings, skipping empty values", () => {
    expect(qs({ a: 1, b: "", c: undefined, d: false, e: "x y" })).toBe("?a=1&d=false&e=x+y");
    expect(qs({})).toBe("");
  });
});

describe("assessment vocabulary", () => {
  it("never describes a potential match as a confirmed breach", () => {
    expect(STATE_LABEL.potential_impact).not.toMatch(/confirm|compromise|breach/i);
    expect(STATE_HELP.potential_impact).toMatch(/NOT established/);
    expect(STATE_HELP.no_match_found).toMatch(/not proof of safety/i);
  });
  it("mirrors the backend relationship rules", () => {
    expect(REL_RULES.USES_VENDOR).toEqual([["client", "vendor"]]);
    expect(REL_RULES.MANAGES_FOR).toEqual([["vendor", "client"]]);
  });
});
