"""Alert condition DSL.

A condition is a small JSON tree. Leaves count failing findings that match a
filter; boolean nodes combine leaves. The vocabulary here is mirrored by
ui/app/(prowler)/alerts/_types/index.ts and the two must stay in sync.
"""

from uuid import UUID

from django.db.models import Q

SCHEMA_VERSION = 1

OP_AND = "and"
OP_OR = "or"
OP_NOT = "not"
OP_COUNT_GTE = "count_gte"
OP_COUNT_LTE = "count_lte"
OP_ANY = "any"
OP_NONE = "none"

GROUP_OPS = frozenset({OP_AND, OP_OR})
COUNT_OPS = frozenset({OP_COUNT_GTE, OP_COUNT_LTE})
LEAF_OPS = frozenset({OP_COUNT_GTE, OP_COUNT_LTE, OP_ANY, OP_NONE})
# Leaves whose matches are the findings a notification should talk about.
# `none` and `count_lte` hold when findings are absent, so they contribute none.
POSITIVE_LEAF_OPS = frozenset({OP_COUNT_GTE, OP_ANY})

SEVERITY_VALUES = frozenset({"critical", "high", "medium", "low", "informational"})
DELTA_VALUES = frozenset({"new", "changed"})

MAX_DEPTH = 5
MAX_NODES = 50
MAX_CHILDREN = 20
MAX_FILTER_VALUES = 200
MAX_VALUE_LENGTH = 512
MAX_COUNT_VALUE = 10_000_000

# DSL field -> Finding ORM lookup. Array columns use `overlap`, scalars use `in`.
FILTER_FIELD_LOOKUPS = {
    "severity": "severity__in",
    "delta": "delta__in",
    "check_id": "check_id__in",
    # Finding groups are keyed by check id.
    "finding_group_id": "check_id__in",
    "categories": "categories__overlap",
    "resource_regions": "resource_regions__overlap",
    "resource_services": "resource_services__overlap",
    "resource_types": "resource_types__overlap",
    "resource_uid": "resources__uid__in",
    "resource_groups": "resource_groups__in",
    "provider_id": "scan__provider_id__in",
    "provider_type": "scan__provider__provider__in",
}

# Fields whose lookup joins a to-many relation and can duplicate rows.
MULTI_ROW_FIELDS = frozenset({"resource_uid"})

# Findings list filter key -> DSL field, used to seed a rule from the UI filters.
FINDINGS_FILTER_TO_FIELD = {
    "provider_type": "provider_type",
    "provider_type__in": "provider_type",
    "provider": "provider_id",
    "provider__in": "provider_id",
    "provider_id": "provider_id",
    "provider_id__in": "provider_id",
    "severity": "severity",
    "severity__in": "severity",
    "delta": "delta",
    "delta__in": "delta",
    "region": "resource_regions",
    "region__in": "resource_regions",
    "service": "resource_services",
    "service__in": "resource_services",
    "resource_type": "resource_types",
    "resource_type__in": "resource_types",
    "category": "categories",
    "category__in": "categories",
    "resource_groups": "resource_groups",
    "resource_groups__in": "resource_groups",
    "check_id": "check_id",
    "check_id__in": "check_id",
    "finding_group_id": "finding_group_id",
    "resource_uid": "resource_uid",
    "resource_uid__in": "resource_uid",
}

# Inverse of the above, used to build the "open in Findings" hint.
FIELD_TO_FINDINGS_FILTER = {
    "provider_type": "filter[provider_type__in]",
    "provider_id": "filter[provider_id__in]",
    "severity": "filter[severity__in]",
    "delta": "filter[delta]",
    "resource_regions": "filter[region__in]",
    "resource_services": "filter[service__in]",
    "resource_types": "filter[resource_type__in]",
    "categories": "filter[category__in]",
    "resource_groups": "filter[resource_groups__in]",
    "check_id": "filter[check_id__in]",
    "finding_group_id": "filter[finding_group_id]",
    "resource_uid": "filter[resource_uid__in]",
}


class ConditionError(ValueError):
    """The condition is not a valid alert DSL tree."""


def _validate_filter(raw_filter) -> dict:
    if not isinstance(raw_filter, dict) or not raw_filter:
        raise ConditionError("`filter` must be a non-empty object.")

    cleaned = {}
    for field, values in raw_filter.items():
        if field not in FILTER_FIELD_LOOKUPS:
            raise ConditionError(f"Unknown filter field: {field!r}.")
        if not isinstance(values, list) or not values:
            raise ConditionError(f"`{field}` must be a non-empty list of strings.")
        if len(values) > MAX_FILTER_VALUES:
            raise ConditionError(
                f"`{field}` accepts at most {MAX_FILTER_VALUES} values."
            )
        if not all(
            isinstance(value, str) and 0 < len(value) <= MAX_VALUE_LENGTH
            for value in values
        ):
            raise ConditionError(f"`{field}` must contain only non-empty strings.")

        if field == "severity":
            invalid = set(values) - SEVERITY_VALUES
            if invalid:
                raise ConditionError(f"Invalid severity values: {sorted(invalid)}.")
        elif field == "delta":
            invalid = set(values) - DELTA_VALUES
            if invalid:
                raise ConditionError(f"Invalid delta values: {sorted(invalid)}.")
        elif field == "provider_id":
            for value in values:
                try:
                    UUID(value)
                except ValueError:
                    raise ConditionError(
                        f"`provider_id` values must be UUIDs, got {value!r}."
                    ) from None

        cleaned[field] = list(dict.fromkeys(values))
    return cleaned


def _validate_node(node, depth: int, counter: list) -> dict:
    if depth > MAX_DEPTH:
        raise ConditionError(f"Condition is nested deeper than {MAX_DEPTH} levels.")
    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise ConditionError(f"Condition has more than {MAX_NODES} nodes.")
    if not isinstance(node, dict):
        raise ConditionError("Each condition node must be an object.")

    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ConditionError(f"`{op}` needs a non-empty `children` list.")
        if len(children) > MAX_CHILDREN:
            raise ConditionError(f"`{op}` accepts at most {MAX_CHILDREN} children.")
        return {
            "op": op,
            "children": [
                _validate_node(child, depth + 1, counter) for child in children
            ],
        }

    if op == OP_NOT:
        if "child" not in node:
            raise ConditionError("`not` needs a `child`.")
        return {"op": op, "child": _validate_node(node["child"], depth + 1, counter)}

    if op in LEAF_OPS:
        cleaned = {"op": op, "filter": _validate_filter(node.get("filter"))}
        if op in COUNT_OPS:
            value = node.get("value")
            # bool is an int subclass; a threshold of `true` is a client bug.
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= MAX_COUNT_VALUE
            ):
                raise ConditionError(
                    f"`{op}` needs an integer `value` between 0 and {MAX_COUNT_VALUE}."
                )
            cleaned["value"] = value
        return cleaned

    raise ConditionError(f"Unknown condition operator: {op!r}.")


def validate_condition(condition) -> dict:
    """Return a normalized copy of `condition` or raise ConditionError."""
    return _validate_node(condition, depth=1, counter=[0])


def filter_to_q(leaf_filter: dict) -> Q:
    """AND of every field in a leaf filter, as a Finding queryset Q."""
    query = Q()
    for field, values in leaf_filter.items():
        query &= Q(**{FILTER_FIELD_LOOKUPS[field]: values})
    return query


def filter_needs_distinct(leaf_filter: dict) -> bool:
    return any(field in MULTI_ROW_FIELDS for field in leaf_filter)


def iter_leaves(condition: dict):
    if "filter" in condition:
        yield condition
    elif "child" in condition:
        yield from iter_leaves(condition["child"])
    else:
        for child in condition.get("children", []):
            yield from iter_leaves(child)


def findings_filter_hint(condition: dict) -> dict:
    """Findings-page filters equivalent to the condition's leaves, merged."""
    hint: dict[str, list[str]] = {}
    for leaf in iter_leaves(condition):
        for field, values in leaf["filter"].items():
            key = FIELD_TO_FINDINGS_FILTER[field]
            merged = hint.setdefault(key, [])
            merged.extend(value for value in values if value not in merged)
    return hint


def _bag_values(raw) -> list[str]:
    items = raw if isinstance(raw, list) else [raw]
    values = []
    for item in items:
        if not isinstance(item, str):
            continue
        values.extend(part.strip() for part in item.split(",") if part.strip())
    return list(dict.fromkeys(values))


def condition_from_filter_bag(filter_bag: dict) -> dict:
    """Build a `count_gte 1` condition from Findings-page filters.

    Keys outside the alert vocabulary (status, muted, scan, dates...) are
    dropped: an alert always evaluates current failing, unmuted findings.
    """
    if not isinstance(filter_bag, dict):
        raise ConditionError("`filter_bag` must be an object.")

    leaf_filter: dict[str, list[str]] = {}
    for raw_key, raw_value in filter_bag.items():
        key = str(raw_key)
        if key.startswith("filter[") and key.endswith("]"):
            key = key[len("filter[") : -1]
        field = FINDINGS_FILTER_TO_FIELD.get(key)
        if field is None:
            continue
        values = _bag_values(raw_value)
        if not values:
            continue
        merged = leaf_filter.setdefault(field, [])
        merged.extend(value for value in values if value not in merged)

    if not leaf_filter:
        raise ConditionError(
            "None of the selected filters can be used in an alert. Filter by "
            "severity, provider, region, service, resource type, category or check."
        )

    return validate_condition({"op": OP_COUNT_GTE, "filter": leaf_filter, "value": 1})
