import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "@/components/ui";
import { CASE_STATUS_LABEL, REPORT_STATUS_LABEL, TASK_STATUS_LABEL, VERIFICATION_LABEL } from "@/lib/labels";

describe("week 3 presentation", () => {
  it("shows severity as a word and a shape, not just a colour", () => {
    render(<SeverityBadge value="critical" />);
    const badge = screen.getByTitle("Severity: Critical");
    expect(badge).toHaveTextContent("Critical");
    expect(badge.textContent).toContain("▲▲▲");
  });

  it("says plainly when the sources state no severity", () => {
    render(<SeverityBadge value={null} />);
    expect(screen.getByTitle("The sources do not state a severity")).toBeInTheDocument();
  });

  it("keeps completion and verification as separate vocabularies", () => {
    expect(TASK_STATUS_LABEL.done).toBe("Completed");
    expect(VERIFICATION_LABEL.unverified).toBe("Not verified");
    expect(Object.values(TASK_STATUS_LABEL)).not.toContain("Verified");
  });

  it("labels every lifecycle phase and report job state", () => {
    expect(CASE_STATUS_LABEL.evidence_collection).toBe("Evidence collection");
    expect(CASE_STATUS_LABEL.remediation).toBe("Remediation");
    expect(Object.keys(REPORT_STATUS_LABEL)).toEqual(["queued", "processing", "completed", "failed"]);
  });
});
