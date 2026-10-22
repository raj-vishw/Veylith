"""Pure unit tests for the deterministic matching rules: exact, alias, version range, missing version, ambiguous."""
import pytest

from app.services.matching import (
    AffectedSpec,
    InventoryProduct,
    best_match,
    decide_state,
    normalize_name,
    parse_cpe,
    version_status,
)


def inv(name="Insight Agent", vendor="Acme Analytics Inc.", version="4.1.0", cpe="", aliases=(), vendor_aliases=(), package=""):
    return InventoryProduct(vendor_name=vendor, vendor_aliases=tuple(vendor_aliases), name=name, aliases=tuple(aliases), package_name=package, version=version, cpe=cpe)


def spec(vendor="acme_analytics", product="insight_agent", cpe=True, **kw):
    c = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*" if cpe else ""
    return AffectedSpec(cpe=c, vendor_norm=normalize_name(vendor, vendor=True), product_norm=normalize_name(product), **kw)


# ---- normalisation ------------------------------------------------------------------------------
def test_normalize_name():
    assert normalize_name("Insight_Agent") == "insight agent"
    assert normalize_name("Acme Analytics, Inc.", vendor=True) == "acme analytics"
    assert normalize_name("Inc", vendor=True) == "inc"  # never normalises a name to nothing


def test_parse_cpe():
    c = parse_cpe("cpe:2.3:a:acme_analytics:insight_agent:4.1.0:*:*:*:*:*:*:*")
    assert (c.part, c.vendor, c.product, c.version) == ("a", "acme_analytics", "insight_agent", "4.1.0")
    assert parse_cpe("not a cpe") is None
    assert parse_cpe("") is None


# ---- version ranges -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "installed,kw,expected",
    [
        ("4.1.0", dict(end_excluding="4.2.1"), "in_range"),
        ("4.2.1", dict(end_excluding="4.2.1"), "out_of_range"),  # the fixed version is not affected
        ("4.2.0", dict(end_including="4.2.0"), "in_range"),
        ("2.0", dict(start_including="2.0", end_including="2.5.3"), "in_range"),
        ("1.9.9", dict(start_including="2.0", end_including="2.5.3"), "out_of_range"),
        ("2.0", dict(start_excluding="2.0", end_including="2.5.3"), "out_of_range"),
        ("2.5.3", dict(start_including="2.0", end_including="2.5.3"), "in_range"),
        ("2.10.0", dict(start_including="2.9", end_excluding="3.0"), "in_range"),  # numeric, not lexicographic
        ("v4.1.0", dict(end_excluding="4.2.1"), "in_range"),
        ("1.8.0", dict(exact_version="1.8.0"), "in_range"),
        ("1.9.0", dict(exact_version="1.8.0"), "out_of_range"),
        ("1.0.0", dict(), "in_range"),  # every version listed as affected
    ],
)
def test_version_ranges(installed, kw, expected):
    assert version_status(installed, spec(**kw)) == expected


def test_missing_or_unparseable_version_is_unknown_not_a_guess():
    assert version_status("", spec(end_excluding="4.2.1")) == "unknown"
    assert version_status("latest-stable", spec(end_excluding="4.2.1")) == "unsupported"  # a version exists but cannot be interpreted
    assert version_status("4.1.0", spec(end_excluding="banana")) == "unsupported"
    assert version_status("4.1.0", spec(exact_version="?")) == "unknown"  # KEV-style: product known, versions not


def test_missing_version_still_matches_when_all_versions_are_affected():
    assert version_status("", spec()) == "in_range"


# ---- identity -----------------------------------------------------------------------------------
def test_exact_cpe_identity_wins():
    r = best_match(inv(cpe="cpe:2.3:a:acme_analytics:insight_agent:4.1.0:*:*:*:*:*:*:*"), [spec(end_excluding="4.2.1")])
    assert (r.match_type, r.version_status) == ("cpe", "in_range")
    assert decide_state(r) == "potential_impact"


def test_name_match_when_inventory_has_no_cpe():
    r = best_match(inv(), [spec(end_excluding="4.2.1")])
    assert r.match_type == "name" and decide_state(r) == "potential_impact"


def test_alias_match():
    r = best_match(inv(name="Insight Telemetry Agent", aliases=["insight-agent"]), [spec(end_excluding="4.2.1")])
    assert r.match_type == "alias"
    r2 = best_match(inv(vendor="Acme", vendor_aliases=["Acme Analytics"]), [spec(end_excluding="4.2.1")])
    assert r2.match_type == "alias"


def test_conflicting_cpe_identities_never_match_by_name():
    r = best_match(inv(cpe="cpe:2.3:a:other_vendor:other_product:1.0:*:*:*:*:*:*:*"), [spec()])
    assert r.match_type is None and decide_state(r) is None


def test_similar_product_name_is_ambiguous_and_never_a_firm_match():
    r = best_match(inv(name="Insight Agent"), [spec(product="insight_agent_pro", end_excluding="9.0")])
    assert r.match_type == "fuzzy"
    assert decide_state(r) == "insufficient_data"


def test_same_product_name_under_a_different_vendor_does_not_match():
    r = best_match(inv(), [spec(vendor="umbrella_hosting", product="insight_agent")])
    assert r.match_type is None


def test_unrelated_product_does_not_match():
    r = best_match(inv(), [spec(vendor="umbrella_hosting", product="cloud_panel", end_excluding="3.3")])
    assert decide_state(r) is None


def test_advisory_without_product_identity_cannot_match():
    r = best_match(inv(), [AffectedSpec()])
    assert r.match_type is None


def test_out_of_range_version_creates_no_assessment():
    r = best_match(inv(version="4.2.1"), [spec(end_excluding="4.2.1")])
    assert r.version_status == "out_of_range" and decide_state(r) is None


def test_missing_version_yields_insufficient_data_not_potential_impact():
    r = best_match(inv(version=""), [spec(end_excluding="4.2.1")])
    assert decide_state(r) == "insufficient_data"


def test_best_of_several_affected_entries():
    r = best_match(inv(version="4.1.0"), [spec(end_excluding="4.0.0"), spec(start_including="4.0.0", end_excluding="4.2.1")])
    assert r.version_status == "in_range"


def test_engine_never_produces_a_compromise_state():
    cases = [inv(), inv(version=""), inv(name="Insight Agent Plus")]
    for p in cases:
        for s in (spec(), spec(end_excluding="4.2.1"), spec(product="insight_agent_pro")):
            assert decide_state(best_match(p, [s])) in (None, "potential_impact", "insufficient_data")
