import type { FieldDef } from "@/components/form";
import { ACCESS_LEVELS, ASSET_TYPES, LEVELS } from "@/lib/labels";

export const VENDOR_FIELDS: FieldDef[] = [
  { name: "name", label: "Vendor name", required: true, maxLength: 200 },
  { name: "website", label: "Official website", placeholder: "vendor.com", hint: "Normalised to a bare domain. A domain is a lead, not proof of identity." },
  { name: "category", label: "Category", placeholder: "analytics, backup, identity…" },
  { name: "description", label: "Product or service description", type: "textarea" },
  { name: "criticality", label: "Business criticality", type: "select", options: LEVELS, required: true },
  { name: "access_level", label: "Access granted", type: "select", options: ACCESS_LEVELS, required: true },
  { name: "integration_type", label: "Integration type", placeholder: "OAuth app, agent, API key…" },
  { name: "owner", label: "Internal owner / team" },
  { name: "review_status", label: "Review status", type: "select", options: ["unreviewed", "in_review", "reviewed"], required: true },
  { name: "last_reviewed_at", label: "Last reviewed", type: "date" },
  { name: "confidence", label: "Confidence in these facts", type: "select", options: ["low", "medium", "high"], required: true },
  { name: "source", label: "Source of these facts", placeholder: "manual, questionnaire, contract…" },
  { name: "notes", label: "Analyst notes", type: "textarea" },
];

export const PRODUCT_FIELDS: FieldDef[] = [
  { name: "name", label: "Product name", required: true, maxLength: 200 },
  { name: "version", label: "Deployed version", hint: "Leave empty if unknown. An unknown version produces 'insufficient data', never a guess." },
  { name: "cpe", label: "CPE identifier (optional)", placeholder: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", hint: "An exact identifier gives the strongest match." },
  { name: "package_name", label: "Package name (optional)" },
  { name: "ecosystem", label: "Version scheme", type: "select", options: ["generic", "pypi", "npm", "semver"], required: true, hint: "How versions are compared: PEP 440 (generic / pypi) or Semantic Versioning (npm / semver). Versions that cannot be interpreted are never guessed." },
  { name: "confidence", label: "Confidence in these facts", type: "select", options: ["low", "medium", "high"], required: true },
];

export const ASSET_FIELDS: FieldDef[] = [
  { name: "name", label: "Asset name", required: true, maxLength: 200 },
  { name: "type", label: "Type", type: "select", options: ASSET_TYPES, required: true },
  { name: "environment", label: "Environment", type: "select", options: ["production", "staging", "development", "other"], required: true },
  { name: "criticality", label: "Business criticality", type: "select", options: LEVELS, required: true },
  { name: "data_sensitivity", label: "Data sensitivity", type: "select", options: ["public", "internal", "confidential", "restricted"], required: true },
  { name: "product_name", label: "Product name (optional)", hint: "Descriptive only. Advisory matching uses the vendor products you record on the vendor page." },
  { name: "product_version", label: "Product version (optional)" },
  { name: "source", label: "Source of this record", placeholder: "manual, scan, questionnaire…" },
  { name: "verification_status", label: "Verification", type: "select", options: ["unverified", "verified", "disputed", "stale"], required: true },
  { name: "internet_exposed", label: "Internet exposed", type: "checkbox" },
  { name: "description", label: "Description", type: "textarea" },
];
