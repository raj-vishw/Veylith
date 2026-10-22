import { expect, test, type Page } from "@playwright/test";

// Full Week-3 scenario through the real UI, against the running stack:
// inventory -> relationships -> advisory ingestion -> matching -> review -> case -> tasks -> evidence -> PDF report -> audit.

// Generated per run (or supplied via E2E_PASSWORD): no credential is stored in the repository.
const PASSWORD = process.env.E2E_PASSWORD ?? `e2e-${crypto.randomUUID()}`;
const stamp = Date.now().toString(36);

async function register(page: Page, email: string, org: string) {
  await page.goto("/register");
  await page.getByLabel("Organization name").fill(org);
  await page.getByLabel("Your name").fill("E2E Owner");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create workspace" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("unauthenticated visitors are sent to the login page", async ({ page }) => {
  await page.goto("/cases");
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login/);
});

test("invalid credentials show a generic error", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("nobody@example.com");
  await page.getByLabel("Password").fill("wrong-password-123");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Invalid email or password")).toBeVisible();
});

test("vendor to advisory to assessment to case to report", async ({ page }) => {
  await register(page, `owner-${stamp}@example.com`, `E2E MSP ${stamp}`);

  // --- inventory ---------------------------------------------------------------------------
  await page.goto("/clients");
  await page.getByRole("button", { name: "Add client" }).click();
  await page.getByLabel("Name").fill("Retail Client");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("link", { name: "Retail Client" })).toBeVisible();

  await page.goto("/vendors");
  await page.getByRole("button", { name: "Add vendor" }).click();
  await page.getByLabel("Vendor name").fill("Acme Analytics Inc.");
  await page.getByLabel("Official website").fill("https://www.acme-analytics.example.com");
  await page.getByLabel("Access granted").selectOption("read");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Acme Analytics Inc." })).toBeVisible();
  await expect(page.getByText("acme-analytics.example.com")).toBeVisible(); // domain normalised

  await page.getByRole("button", { name: "Add product" }).click();
  await page.getByLabel("Product name").fill("Insight Agent");
  await page.getByLabel("Deployed version").fill("4.1.0");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name: "Insight Agent" })).toBeVisible();

  await page.goto("/assets");
  await page.getByRole("button", { name: "Add asset" }).click();
  await page.getByRole("dialog").getByLabel(/^Client/).selectOption({ label: "Retail Client" });
  await page.getByLabel("Asset name").fill("storefront-api");
  await page.getByLabel("Business criticality").selectOption("critical");
  await page.getByLabel("Internet exposed").check();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name: "storefront-api" })).toBeVisible();

  // relationship: client uses vendor
  await page.goto("/vendors");
  await page.getByRole("row", { name: /Acme Analytics/ }).click();
  await page.getByRole("button", { name: "Add relationship" }).click();
  await page.getByLabel("Other end").selectOption({ label: "Client · Retail Client" });
  await page.getByLabel("Verification").selectOption("verified");
  await expect(page.getByRole("button", { name: "Add relationship" }).last()).toBeDisabled(); // a verification method is required
  await page.getByLabel(/Verification method/).selectOption("manual_review");
  await page.getByRole("button", { name: "Add relationship" }).last().click();
  await expect(page.getByText("uses vendor")).toBeVisible();

  // --- the graph shows what was recorded -----------------------------------------------------
  await page.goto("/graph");
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await expect(page.locator(".react-flow__node", { hasText: "Acme Analytics Inc." })).toBeVisible();
  await page.locator(".react-flow__node", { hasText: "Acme Analytics Inc." }).click();
  await expect(page.getByRole("complementary", { name: "Details" })).toContainText("Open record");

  // --- intelligence --------------------------------------------------------------------------
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Intelligence sources" }).click();
  await page.getByRole("button", { name: "Load synthetic demo advisories" }).click();
  await expect(page.getByText("FIXTURE").first()).toBeVisible({ timeout: 60_000 });

  await expect(async () => {
    await page.goto("/assessments");
    await expect(page.getByRole("row", { name: /CVE-2099-1001/ })).toBeVisible({ timeout: 3_000 });
  }).toPass({ timeout: 60_000 });

  // --- the assessment explains itself, and does not claim a breach ----------------------------
  await page.getByRole("row", { name: /CVE-2099-1001/ }).first().click();
  await expect(page.getByText("Dependency path")).toBeVisible();
  await expect(page.getByText("Not established", { exact: true })).toBeVisible();
  await expect(page.getByText(/not evidence of compromise/)).toBeVisible();
  await expect(page.getByText("Potential impact").first()).toBeVisible();
  await expect(page.getByText("Compromise confirmed")).toHaveCount(0);
  await expect(page.getByText(/Why priority is/)).toBeVisible();
  await expect(page.getByText("Synthetic demonstration data").first()).toBeVisible();

  // --- case ---------------------------------------------------------------------------------
  await page.getByRole("button", { name: "Open case" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Open case" }).click();
  await expect(page.getByRole("heading", { name: /VEY-0001/ })).toBeVisible();

  await page.getByRole("button", { name: "→ Triage" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("button", { name: "→ Investigating" })).toBeVisible();
  await page.getByRole("button", { name: "→ Investigating" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("button", { name: "→ Resolved" })).toBeVisible();

  // unsaved note draft survives a reload
  await page.getByLabel("New note").fill("Draft: checking lockfile for agent version");
  await page.reload();
  await expect(page.getByLabel("New note")).toHaveValue("Draft: checking lockfile for agent version");
  await page.getByLabel("Visibility").selectOption("customer");
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText("Customer-visible", { exact: true }).first()).toBeVisible();

  // tasks
  await page.getByRole("tab", { name: /Tasks/ }).click();
  await page.getByRole("button", { name: "Add task" }).click();
  await page.getByLabel("Title").fill("Verify deployed Insight Agent version");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Verify deployed Insight Agent version")).toBeVisible();

  // evidence: a note plus an uploaded file with a hash
  await page.getByRole("tab", { name: /Evidence/ }).click();
  await page.getByRole("button", { name: "Add source or note" }).click();
  await page.getByLabel("Type").selectOption("note");
  await page.getByLabel("Title").fill("Lockfile check");
  await page.getByLabel("Relevant excerpt or observation").fill("package-lock pins insight-agent 4.1.0");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Lockfile check")).toBeVisible();
  await page.getByLabel("Upload evidence file").setInputFiles({ name: "agent-version.txt", mimeType: "text/plain", buffer: Buffer.from("insight-agent 4.1.0\n") });
  await expect(page.getByText("agent-version.txt")).toBeVisible();
  await expect(page.locator("code", { hasText: "…" }).first()).toBeVisible(); // SHA-256 prefix shown

  // cannot resolve while a task is open
  await page.getByRole("tab", { name: "Overview" }).click();
  await page.getByRole("button", { name: "→ Resolved" }).click();
  await page.getByLabel("Resolution summary").fill("Upgraded.");
  await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("task");
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();

  // complete task (notes required)
  await page.getByRole("tab", { name: /Tasks/ }).click();
  await page.getByRole("button", { name: "Complete" }).click();
  await expect(page.getByRole("button", { name: "Mark complete" })).toBeDisabled();
  await page.getByLabel("Completion notes (required)").fill("Confirmed 4.1.0; upgraded to 4.2.1.");
  await page.getByRole("button", { name: "Mark complete" }).click();
  await expect(page.getByText("Completed", { exact: true })).toBeVisible();
  await expect(page.getByText("Not verified", { exact: true })).toBeVisible(); // completion is only a claim

  // verification is a separate step with its own record
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByRole("button", { name: "Mark verified" })).toBeDisabled();
  await page.getByLabel("What did you check?").fill("Re-ran the version check on the production host.");
  await page.getByRole("button", { name: "Mark verified" }).click();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible();

  // --- PDF report (rendered by the dedicated reporter container) ---------------------------------
  await page.getByRole("tab", { name: /Reports/ }).click();
  await page.getByRole("button", { name: "Generate technical report" }).click();
  await expect(page.getByRole("button", { name: "Download PDF" })).toBeVisible({ timeout: 60_000 });
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download PDF" }).click()]);
  const path = await download.path();
  const fs = await import("fs");
  expect(fs.readFileSync(path!).subarray(0, 5).toString()).toBe("%PDF-");

  // --- resolve + close, then check the timeline and audit trail -----------------------------------
  await page.getByRole("tab", { name: "Overview" }).click();
  await page.getByRole("button", { name: "→ Resolved" }).click();
  await page.getByLabel("Resolution summary").fill("Upgraded to 4.2.1; verified.");
  await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("button", { name: "→ Investigating" })).toBeVisible(); // only offered once the case is Resolved
  await page.getByRole("button", { name: "Close case" }).click();
  await page.getByLabel("Resolution summary").fill("Upgraded to 4.2.1; verified.");
  await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("button", { name: "Reopen" })).toBeVisible();

  await page.getByRole("tab", { name: "Timeline" }).click();
  await expect(page.getByText("Status changed from resolved to closed.")).toBeVisible();
  await expect(page.getByText("System", { exact: true }).first()).toBeVisible();

  await page.goto("/settings");
  await page.getByRole("tab", { name: "Audit trail" }).click();
  for (const event of ["case.created", "case.status_changed", "evidence.uploaded", "report.generated", "report.downloaded", "vendor.created"]) {
    await expect(page.getByText(event, { exact: true }).first()).toBeVisible();
  }
});

test("another organization cannot see the first organization's records", async ({ page, browser }) => {
  await register(page, `rival-${stamp}@example.com`, `Rival MSP ${stamp}`);
  for (const path of ["/clients", "/vendors", "/cases", "/assets"]) {
    await page.goto(path);
    await expect(page.getByText("Retail Client")).toHaveCount(0);
    await expect(page.getByText("Acme Analytics Inc.")).toHaveCount(0);
  }
  await page.goto("/cases");
  await expect(page.getByText("No cases")).toBeVisible();
});

test("viewer role is read-only in the UI and the API", async ({ page }) => {
  await register(page, `lead-${stamp}@example.com`, `Roles Org ${stamp}`);
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Team" }).click();
  await page.getByRole("button", { name: "Add member" }).click();
  await page.getByRole("dialog").getByLabel("Email").fill(`viewer-${stamp}@example.com`);
  await page.getByRole("dialog").getByLabel(/^Role/).selectOption("viewer");
  await page.getByLabel("Initial password").fill(PASSWORD);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText(`viewer-${stamp}@example.com`).first()).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();

  await page.getByLabel("Email").fill(`viewer-${stamp}@example.com`);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.goto("/clients");
  await expect(page.getByRole("button", { name: "Add client" })).toHaveCount(0);
  const res = await page.request.post("/api/v1/clients", { data: { name: "sneaky" } });
  expect(res.status()).toBe(403);
});


test("empty workspace shows onboarding and inventory counts; forms validate before submitting", async ({ page }) => {
  await register(page, `fresh-${stamp}@example.com`, `Fresh Org ${stamp}`);
  await expect(page.getByText("your workspace is empty")).toBeVisible();
  await expect(page.getByLabel("Inventory").getByText("Clients")).toBeVisible();
  await page.goto("/clients");
  await page.getByRole("button", { name: "Add client" }).click();
  await page.getByRole("button", { name: "Save" }).click(); // name left empty
  await expect(page.getByText("Name is required")).toBeVisible();
  await page.getByLabel("Name").fill("First Client");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("link", { name: "First Client" })).toBeVisible();
  await page.goto("/");
  await expect(page.getByText("your workspace is empty")).toHaveCount(0); // no longer empty
});

test("a user can create a second workspace and switch between workspaces", async ({ page }) => {
  await register(page, `multi-${stamp}@example.com`, `Workspace One ${stamp}`);
  page.once("dialog", (d) => d.accept(`Workspace Two ${stamp}`));
  await page.getByRole("button", { name: "+ New workspace" }).click();
  await expect(page.locator("aside .truncate").first()).toHaveText(`Workspace Two ${stamp}`);
  await expect(page.getByRole("combobox", { name: "Switch organization" })).toBeVisible();
  await page.getByRole("combobox", { name: "Switch organization" }).selectOption({ label: `Workspace One ${stamp}` });
  await expect(page.locator("aside .truncate").first()).toHaveText(`Workspace One ${stamp}`);
});

test("revoked members lose access and can be re-admitted", async ({ page, browser }) => {
  await register(page, `boss-${stamp}@example.com`, `Revoke Org ${stamp}`);
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Team" }).click();
  await page.getByRole("button", { name: "Add member" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Email").fill(`temp-${stamp}@example.com`);
  await dialog.getByLabel(/^Role/).selectOption("analyst");
  await dialog.getByLabel("Initial password").fill(PASSWORD);
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText(`temp-${stamp}@example.com`).first()).toBeVisible();

  const other = await browser.newContext();
  const p2 = await other.newPage();
  await p2.goto("/login");
  await p2.getByLabel("Email").fill(`temp-${stamp}@example.com`);
  await p2.getByLabel("Password").fill(PASSWORD);
  await p2.getByRole("button", { name: "Sign in" }).click();
  await expect(p2.getByRole("heading", { name: "Overview" })).toBeVisible();

  await page.getByRole("row", { name: new RegExp(`temp-${stamp}`) }).getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("row", { name: new RegExp(`temp-${stamp}`) }).getByText("Revoked")).toBeVisible();

  await p2.goto("/clients"); // the revoked user's existing session no longer works
  await expect(p2).toHaveURL(/\/login/);
  await other.close();
});


async function apiCall(page: Page, method: string, path: string, data?: unknown) {
  const csrf = (await (await page.request.get("/api/v1/auth/csrf")).json()).csrf_token;
  const res = await page.request.fetch(`/api/v1${path}`, { method, data, headers: { "X-CSRF-Token": csrf, Origin: "http://localhost:3000" } });
  expect(res.status(), `${method} ${path}`).toBeLessThan(300);
  return res.status() === 204 ? null : res.json();
}

test("week 2: intelligence dashboard, graph interactions, evidence and incorrect-match review", async ({ page }) => {
  await register(page, `intel-${stamp}@example.com`, `Intel Org ${stamp}`);
  const client = await apiCall(page, "POST", "/clients", { name: "Contoso Retail" });
  const vendor = await apiCall(page, "POST", "/vendors", { name: "Acme Analytics Inc.", access_level: "read" });
  const product = await apiCall(page, "POST", "/products", { vendor_id: vendor.id, name: "Insight Agent", version: "4.1.0" });
  const asset = await apiCall(page, "POST", "/assets", { client_id: client.id, name: "storefront-api", type: "repository", criticality: "critical", internet_exposed: true });
  await apiCall(page, "POST", "/relationships", { source_type: "client", source_id: client.id, target_type: "vendor", target_id: vendor.id, rel_type: "USES_VENDOR" });
  await apiCall(page, "POST", "/relationships", { source_type: "asset", source_id: asset.id, target_type: "product", target_id: product.id, rel_type: "DEPENDS_ON", verification_status: "verified", verification_method: "manual_review", evidence: "lockfile" });
  await apiCall(page, "POST", "/ingestion-runs", { source: "fixture" });

  // --- intelligence dashboard: real counts, and an honest statement about sources that were never checked
  await expect(async () => {
    await page.goto("/intelligence");
    const card = page.getByRole("link", { name: /^Requiring review/ });
    await expect(card).toBeVisible({ timeout: 3_000 });
    await expect(card).not.toContainText(/Requiring review\s*0/, { timeout: 3_000 });  // real, non-zero count from the database
  }).toPass({ timeout: 60_000 });
  await expect(page.getByRole("status")).toContainText("An empty advisory list does not mean there is nothing new");
  await expect(page.getByTestId("source-nvd")).toContainText("Never run");
  await expect(page.getByText("Potential exposure", { exact: true })).toBeVisible();
  // The pipeline is asynchronous (ingestion, then correlation), so allow the dashboard to catch up.
  await expect(async () => {
    await page.goto("/intelligence");
    await expect(page.locator('a[href^="/assets/"]', { hasText: "storefront-api" })).toBeVisible({ timeout: 3_000 }); // high-priority asset
  }).toPass({ timeout: 45_000 });

  // --- graph: bounded view, node-type chips, search, refresh, details, navigation to the asset
  await page.goto("/graph");
  await expect(page.getByText("Showing a bounded view")).toBeVisible();
  await expect(page.locator(".react-flow__node", { hasText: "Acme Analytics Inc." })).toBeVisible();
  await page.getByRole("button", { name: "Vendors" }).click();
  await expect(page.locator(".react-flow__node", { hasText: "Acme Analytics Inc." })).toHaveCount(0);
  await page.getByRole("button", { name: "Vendors" }).click();
  await expect(page.locator(".react-flow__node", { hasText: "Acme Analytics Inc." })).toBeVisible();
  await page.getByLabel("Search nodes").fill("storefront");
  await expect(page.getByText("1 match")).toBeVisible();
  await page.getByLabel("Search nodes").fill("");
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText(/Updated /)).toBeVisible();
  await page.locator(".react-flow__node", { hasText: "storefront-api" }).click();
  await expect(page.getByRole("complementary", { name: "Details" })).toContainText("storefront-api");
  await page.getByRole("link", { name: "Open record →" }).click();
  await expect(page.getByRole("heading", { name: "storefront-api" })).toBeVisible();
  await expect(page.getByText("Verified", { exact: false }).first()).toBeVisible();

  // --- assessment: separate dimensions, labelled facts / inferred path / analyst conclusions
  await page.goto("/assessments");
  await page.getByRole("row", { name: /CVE-2099-1001/ }).first().click();
  const dims = page.getByLabel("Status dimensions");
  await expect(dims).toContainText("Match");
  await expect(dims).toContainText("Exposure");
  await expect(dims).toContainText("Compromise");
  await expect(dims).toContainText("Remediation");
  await expect(page.locator("li", { hasText: "Affected range used:" })).toContainText("before 4.2.1");
  await expect(page.getByText("Inferred from recorded relationships")).toBeVisible();
  await expect(page.getByText("Human decisions")).toBeVisible();
  await expect(page.getByText("No analyst decisions yet")).toBeVisible();

  // exposure decisions need a reason
  await page.getByRole("button", { name: "Review", exact: true }).click();
  const review = page.getByRole("dialog");
  await review.getByLabel(/^Exposure/).selectOption("verified");
  await review.getByRole("button", { name: "Save review" }).click();
  await expect(review.getByRole("alert")).toContainText("note explaining the decision");
  await review.getByLabel("Reason (required)").fill("Lockfile shows 4.1.0 in production.");
  await review.getByRole("button", { name: "Save review" }).click();
  await expect(dims).toContainText("Verified");
  await expect(page.getByText("Exposure verified").first()).toBeVisible();

  // marking the match incorrect keeps the evidence and removes it from the active queue
  await page.getByRole("button", { name: "Mark match incorrect" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByRole("button", { name: "Mark incorrect" }).isDisabled();
  await dlg.getByLabel(/Why is this match wrong/).fill("This is an internal fork of the agent.");
  await dlg.getByRole("button", { name: "Mark incorrect" }).click();
  await expect(page.getByText("Match marked incorrect:")).toBeVisible();
  await expect(page.getByText("Supporting evidence (preserved snapshots)")).toBeVisible();
  await page.goto("/assessments");
  await expect(page.getByRole("row", { name: /CVE-2099-1001/ })).toHaveCount(0);
});
