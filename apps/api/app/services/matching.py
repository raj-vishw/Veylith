"""Deterministic product matching. No I/O: everything here is pure so it can be tested exhaustively.

Staged strategy (see docs/architecture.md):
  1. exact identifiers (CPE vendor + product)
  2. vendor/product names and aliases
  3. version ranges
  Ambiguous (fuzzy) names are never treated as a match: they are flagged for analyst review."""

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from functools import total_ordering

from packaging.version import InvalidVersion, Version

_CORP_SUFFIXES = {"inc", "llc", "ltd", "corp", "corporation", "co", "company", "gmbh", "plc", "limited", "sa", "ag"}
_ANY = {"", "*", "-"}
FUZZY_THRESHOLD = 0.85


def normalize_name(value: str, *, vendor: bool = False) -> str:
    text = re.sub(r"[^a-z0-9]+", " ", (value or "").lower().replace("_", " ")).strip()
    tokens = text.split()
    if vendor:
        tokens = [t for t in tokens if t not in _CORP_SUFFIXES] or tokens
    return " ".join(tokens)


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str


def parse_cpe(cpe: str) -> Cpe | None:
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = re.split(r"(?<!\\):", cpe)
    if len(parts) < 6:
        return None
    return Cpe(part=parts[2], vendor=parts[3].replace("\\", ""), product=parts[4].replace("\\", ""), version=parts[5].replace("\\", ""))


MATCHER_VERSION = "2.0"
ECOSYSTEMS = ("generic", "pypi", "npm", "semver")
_SEMVER = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$")


@total_ordering
class SemVer:
    """Semantic Versioning 2.0 precedence, including pre-releases (1.0.0-rc.1 < 1.0.0). Build metadata is ignored."""

    __slots__ = ("core", "pre")

    def __init__(self, core: tuple[int, int, int], pre: tuple[str, ...]):
        self.core, self.pre = core, pre

    @staticmethod
    def parse(value: str) -> "SemVer | None":
        m = _SEMVER.match(value.strip())
        if not m:
            return None
        return SemVer((int(m[1]), int(m[2]), int(m[3])), tuple(m[4].split(".")) if m[4] else ())

    def _key(self):
        # A release sorts after any of its pre-releases; numeric identifiers sort before alphanumeric ones.
        ids = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in self.pre)
        return (self.core, 1 if not self.pre else 0, ids)

    def __eq__(self, other):
        return isinstance(other, SemVer) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())


def parse_version(value: str, ecosystem: str = "generic"):
    """Comparable version object for the ecosystem, or None when the text is empty/wildcard or not interpretable.

    generic / pypi  PEP 440 (handles 2.10 > 2.9, rc/post/dev releases); npm / semver  Semantic Versioning 2.0.
    Anything else raises no guess: the caller reports 'unsupported'."""
    value = (value or "").strip().lstrip("vV")
    if value in _ANY:
        return None
    if ecosystem in ("npm", "semver"):
        return SemVer.parse(value)
    try:
        return Version(value)
    except InvalidVersion:
        return None


@dataclass(frozen=True)
class AffectedSpec:
    """Affected-product facts needed for matching (decoupled from the ORM model)."""

    cpe: str = ""
    vendor_norm: str = ""
    product_norm: str = ""
    exact_version: str = ""
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""


@dataclass(frozen=True)
class InventoryProduct:
    vendor_name: str
    vendor_aliases: tuple[str, ...]
    name: str
    aliases: tuple[str, ...]
    package_name: str = ""
    version: str = ""
    cpe: str = ""
    ecosystem: str = "generic"

    def effective_version(self) -> str:
        if self.version.strip():
            return self.version.strip()
        c = parse_cpe(self.cpe)
        return c.version if c and c.version not in _ANY else ""


def inventory_keys(p: InventoryProduct) -> tuple[set[str], set[str]]:
    """(vendor names, product names) normalised, used to find candidate advisories."""
    vendors = {normalize_name(n, vendor=True) for n in (p.vendor_name, *p.vendor_aliases) if n}
    products = {normalize_name(n) for n in (p.name, p.package_name, *p.aliases) if n}
    c = parse_cpe(p.cpe)
    if c:
        vendors.add(normalize_name(c.vendor, vendor=True))
        products.add(normalize_name(c.product))
    return {v for v in vendors if v}, {x for x in products if x}


@dataclass(frozen=True)
class NameMatch:
    match_type: str | None  # cpe | name | alias | fuzzy | None
    detail: str = ""


def match_identity(p: InventoryProduct, spec: AffectedSpec) -> NameMatch:
    inv_cpe = parse_cpe(p.cpe)
    adv_cpe = parse_cpe(spec.cpe)
    # Stage 1: exact identifiers. Two differing CPE identities are conflicting evidence, not a near-match.
    if inv_cpe and adv_cpe:
        same = normalize_name(inv_cpe.vendor, vendor=True) == normalize_name(adv_cpe.vendor, vendor=True) and normalize_name(inv_cpe.product) == normalize_name(adv_cpe.product)
        return NameMatch("cpe", f"CPE {adv_cpe.vendor}:{adv_cpe.product}") if same else NameMatch(None, "CPE identities differ")

    # Stage 2: names and aliases. Vendor AND product must both agree.
    inv_vendor_main = normalize_name(p.vendor_name, vendor=True)
    inv_vendor_alias = {normalize_name(a, vendor=True) for a in p.vendor_aliases}
    inv_prod_main = {normalize_name(n) for n in (p.name, p.package_name) if n}
    inv_prod_alias = {normalize_name(a) for a in p.aliases}

    adv_vendor, adv_product = spec.vendor_norm, spec.product_norm
    if not adv_vendor or not adv_product:
        return NameMatch(None, "advisory lacks product identity")

    vendor_main_hit = adv_vendor == inv_vendor_main
    vendor_alias_hit = adv_vendor in inv_vendor_alias
    if vendor_main_hit or vendor_alias_hit:
        product_main_hit = adv_product in inv_prod_main
        product_alias_hit = adv_product in inv_prod_alias
        if product_main_hit or product_alias_hit:
            via_alias = vendor_alias_hit and not vendor_main_hit or product_alias_hit and not product_main_hit
            return NameMatch("alias" if via_alias else "name", f"{adv_vendor} / {adv_product}")
        # Same vendor, similar but not identical product name: ambiguous, needs a human.
        best = max((SequenceMatcher(None, adv_product, n).ratio() for n in inv_prod_main | inv_prod_alias), default=0.0)
        if best >= FUZZY_THRESHOLD:
            return NameMatch("fuzzy", f"'{adv_product}' is similar to a recorded product name ({best:.0%})")
    return NameMatch(None, "no identity match")


def fixed_version(spec: AffectedSpec) -> str:
    """The first unaffected version when the advisory states an exclusive upper bound; '' when no fix is stated."""
    return spec.end_excluding


def version_status(inventory_version: str, spec: AffectedSpec, ecosystem: str = "generic") -> str:
    """in_range | out_of_range | unknown | unsupported.

    unknown      the inventory has no version, or the advisory does not say which versions are affected
    unsupported  a version exists but cannot be interpreted safely for this ecosystem (never guessed)"""
    has_bounds = any([spec.start_including, spec.start_excluding, spec.end_including, spec.end_excluding])
    exact = spec.exact_version.strip()
    exact_any = exact in _ANY
    if not has_bounds and exact_any:
        return "in_range"  # advisory lists every version as affected
    if not (inventory_version or "").strip() or (inventory_version or "").strip() in _ANY:
        return "unknown"
    if exact == "?":
        return "unknown"  # product named but versions unspecified (CISA KEV)
    installed = parse_version(inventory_version, ecosystem)
    if installed is None:
        return "unsupported"
    if exact and not exact_any and not has_bounds:
        target = parse_version(exact, ecosystem)
        if target is None:
            return "unsupported"
        return "in_range" if installed == target else "out_of_range"
    checks = []
    for raw, op in (
        (spec.start_including, lambda a, b: a >= b),
        (spec.start_excluding, lambda a, b: a > b),
        (spec.end_including, lambda a, b: a <= b),
        (spec.end_excluding, lambda a, b: a < b),
    ):
        if raw:
            bound = parse_version(raw, ecosystem)
            if bound is None:
                return "unsupported"
            checks.append(op(installed, bound))
    return "in_range" if all(checks) else "out_of_range"


@dataclass(frozen=True)
class MatchResult:
    match_type: str | None
    version_status: str
    detail: str = ""
    affected_range: dict | None = None
    matcher_version: str = MATCHER_VERSION

    @property
    def status(self) -> str:
        """The advisory-match status stored on advisory_matches."""
        if self.match_type is None or self.version_status == "out_of_range":
            return "no_match"
        if self.match_type == "fuzzy":
            return "needs_review"
        if self.version_status in ("unknown", "unsupported"):
            return "insufficient_data"
        return "matched"


_RANK = {"cpe": 4, "name": 3, "alias": 2, "fuzzy": 1, None: 0}
_VRANK = {"in_range": 4, "unknown": 3, "unsupported": 2, "out_of_range": 1}


def range_summary(spec: AffectedSpec) -> dict:
    return {
        "exact": spec.exact_version, "start_including": spec.start_including, "start_excluding": spec.start_excluding,
        "end_including": spec.end_including, "end_excluding": spec.end_excluding, "fixed_version": fixed_version(spec), "cpe": spec.cpe,
    }


def best_match(p: InventoryProduct, specs: list[AffectedSpec]) -> MatchResult:
    """Strongest result across all affected-product entries of one advisory (an advisory may list several ranges)."""
    best: MatchResult | None = None
    for spec in specs:
        ident = match_identity(p, spec)
        if ident.match_type is None:
            continue
        status = version_status(p.effective_version(), spec, p.ecosystem)
        candidate = MatchResult(ident.match_type, status, ident.detail, range_summary(spec))
        if best is None or (_VRANK[status], _RANK[ident.match_type]) > (_VRANK[best.version_status], _RANK[best.match_type]):
            best = candidate
    return best or MatchResult(None, "unknown", "no matching affected product")


def decide_state(result: MatchResult) -> str | None:
    """Assessment state implied by a match, or None when no assessment should exist.

    A vulnerability match can only ever produce 'potential_impact' (or 'insufficient_data' when the
    evidence cannot support more). 'confirmed_dependency', 'exposure_verified' and 'compromise_confirmed'
    are analyst-set only: the engine never claims a breach."""
    status = result.status
    if status == "no_match":
        return None
    return "potential_impact" if status == "matched" else "insufficient_data"
