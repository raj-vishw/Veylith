// Display copy for backend enums. The wording keeps "potential" and "confirmed" clearly apart.

export const STATE_LABEL: Record<string, string> = {
  potential_impact: "Potential impact",
  insufficient_data: "Insufficient data",
  confirmed_dependency: "Confirmed dependency",
  exposure_verified: "Exposure verified",
  compromise_confirmed: "Compromise confirmed",
  no_match_found: "No match found",
};

export const STATE_HELP: Record<string, string> = {
  potential_impact: "A recorded product matches an affected product and version. Exposure and compromise are NOT established.",
  insufficient_data: "The available information cannot support a reliable conclusion (unknown version or ambiguous product).",
  confirmed_dependency: "Evidence establishes that the client uses the affected product or service.",
  exposure_verified: "Evidence supports the relevant exposure or vulnerable configuration.",
  compromise_confirmed: "Reliable, verified evidence establishes unauthorized access or compromise.",
  no_match_found: "The inventory no longer contains a matching dependency. This is not proof of safety if the inventory is incomplete.",
};

export const CASE_STATUS_LABEL: Record<string, string> = {
  new: "New",
  triage: "Triage",
  investigating: "Investigating",
  evidence_collection: "Evidence collection",
  remediation: "Remediation",
  resolved: "Resolved",
  closed: "Closed",
};

// A task is "done" in the API; the interface calls it Completed because completion is only the doer's claim.
export const TASK_STATUS_LABEL: Record<string, string> = { open: "Open", in_progress: "In progress", blocked: "Blocked", done: "Completed", cancelled: "Cancelled" };
export const VERIFICATION_LABEL: Record<string, string> = { unverified: "Not verified", verified: "Verified", rejected: "Rejected" };
export const REPORT_STATUS_LABEL: Record<string, string> = { queued: "Queued", processing: "Generating…", completed: "Completed", failed: "Failed" };

export const REL_LABEL: Record<string, string> = {
  USES_VENDOR: "uses vendor",
  CONNECTS_TO: "connects to",
  HAS_ACCESS_TO: "has access to",
  DEPENDS_ON: "depends on",
  HOSTS: "hosts",
  MANAGES_FOR: "manages for",
  SUPPLIED_BY: "supplied by",
  BELONGS_TO: "belongs to",
};

export const MATCH_LABEL: Record<string, string> = {
  cpe: "Exact identifier (CPE)",
  name: "Vendor and product name",
  alias: "Alias match",
  fuzzy: "Ambiguous name — needs review",
};

export const VERSION_LABEL: Record<string, string> = {
  in_range: "Version in affected range",
  out_of_range: "Version outside affected range",
  unknown: "Version unknown",
};

export const ASSET_TYPES = ["repository", "cloud_resource", "saas_application", "business_application", "software_package", "production_service", "identity", "other"];
export const LEVELS = ["low", "medium", "high", "critical"];
export const ACCESS_LEVELS = ["none", "read", "write", "admin"];
export const VERIFICATION_METHODS = ["manual_review", "document", "api", "vendor_confirmation", "other"];
export const REL_TYPES = ["USES_VENDOR", "CONNECTS_TO", "HAS_ACCESS_TO", "DEPENDS_ON", "HOSTS", "MANAGES_FOR"];

/** Which entity types each relationship type may connect (mirrors the backend rules). */
export const REL_RULES: Record<string, [string, string][]> = {
  USES_VENDOR: [["client", "vendor"]],
  CONNECTS_TO: [["vendor", "asset"], ["asset", "asset"], ["vendor", "vendor"]],
  HAS_ACCESS_TO: [["vendor", "asset"], ["product", "asset"]],
  DEPENDS_ON: [["asset", "product"], ["asset", "vendor"], ["asset", "asset"], ["vendor", "vendor"], ["product", "product"]],
  HOSTS: [["asset", "asset"], ["vendor", "asset"]],
  MANAGES_FOR: [["vendor", "client"]],
};
