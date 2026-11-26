import pytest
from alerts import dsl

LEAF = {"op": "count_gte", "filter": {"severity": ["critical"]}, "value": 1}


class TestValidateCondition:
    def test_valid_leaf_is_returned_normalized(self):
        condition = {
            "op": "count_gte",
            "filter": {"severity": ["high", "high", "critical"]},
            "value": 3,
            "ignored": "extra keys are dropped",
        }

        assert dsl.validate_condition(condition) == {
            "op": "count_gte",
            "filter": {"severity": ["high", "critical"]},
            "value": 3,
        }

    def test_nested_boolean_tree_is_accepted(self):
        condition = {
            "op": "and",
            "children": [
                LEAF,
                {"op": "not", "child": {"op": "none", "filter": {"delta": ["new"]}}},
                {
                    "op": "or",
                    "children": [{"op": "any", "filter": {"check_id": ["a"]}}],
                },
            ],
        }

        assert dsl.validate_condition(condition)["op"] == "and"

    @pytest.mark.parametrize(
        "condition",
        [
            None,
            [],
            {},
            {"op": "xor", "children": [LEAF]},
            {"op": "and", "children": []},
            {"op": "not"},
            {"op": "any", "filter": {}},
            {"op": "any", "filter": {"status": ["FAIL"]}},
            {"op": "any", "filter": {"severity": "critical"}},
            {"op": "any", "filter": {"severity": []}},
            {"op": "any", "filter": {"severity": ["catastrophic"]}},
            {"op": "any", "filter": {"delta": ["removed"]}},
            {"op": "any", "filter": {"provider_id": ["not-a-uuid"]}},
            {"op": "any", "filter": {"check_id": [1]}},
            {"op": "count_gte", "filter": {"severity": ["low"]}},
            {"op": "count_gte", "filter": {"severity": ["low"]}, "value": -1},
            {"op": "count_gte", "filter": {"severity": ["low"]}, "value": "1"},
            {"op": "count_lte", "filter": {"severity": ["low"]}, "value": True},
        ],
    )
    def test_invalid_condition_is_rejected(self, condition):
        with pytest.raises(dsl.ConditionError):
            dsl.validate_condition(condition)

    def test_too_deep_tree_is_rejected(self):
        condition = LEAF
        for _ in range(dsl.MAX_DEPTH):
            condition = {"op": "not", "child": condition}

        with pytest.raises(dsl.ConditionError, match="nested deeper"):
            dsl.validate_condition(condition)

    def test_too_many_nodes_are_rejected(self):
        group = {"op": "or", "children": [LEAF] * dsl.MAX_CHILDREN}
        condition = {"op": "and", "children": [group, group, group]}

        with pytest.raises(dsl.ConditionError, match="more than"):
            dsl.validate_condition(condition)


class TestConditionFromFilterBag:
    def test_findings_filters_become_a_count_leaf(self):
        condition = dsl.condition_from_filter_bag(
            {
                "filter[severity__in]": "critical,high",
                "filter[region__in]": ["us-east-1", "eu-west-1"],
                "filter[provider_type__in]": "aws",
                "filter[delta]": "new",
            }
        )

        assert condition == {
            "op": "count_gte",
            "value": 1,
            "filter": {
                "severity": ["critical", "high"],
                "resource_regions": ["us-east-1", "eu-west-1"],
                "provider_type": ["aws"],
                "delta": ["new"],
            },
        }

    def test_filters_outside_the_alert_vocabulary_are_dropped(self):
        condition = dsl.condition_from_filter_bag(
            {
                "filter[status__in]": "FAIL",
                "filter[muted]": "false",
                "filter[scan__in]": "abc",
                "filter[service__in]": "s3",
            }
        )

        assert condition["filter"] == {"resource_services": ["s3"]}

    @pytest.mark.parametrize(
        "filter_bag", [{}, {"filter[status__in]": "FAIL"}, {"filter[severity__in]": ""}]
    )
    def test_bag_without_usable_filters_is_rejected(self, filter_bag):
        with pytest.raises(dsl.ConditionError, match="None of the selected filters"):
            dsl.condition_from_filter_bag(filter_bag)

    def test_invalid_value_is_rejected(self):
        with pytest.raises(dsl.ConditionError, match="Invalid severity"):
            dsl.condition_from_filter_bag({"filter[severity__in]": "bogus"})


def test_findings_filter_hint_merges_leaves_and_round_trips():
    condition = {
        "op": "or",
        "children": [
            {"op": "any", "filter": {"severity": ["critical"], "check_id": ["a"]}},
            {"op": "any", "filter": {"severity": ["critical", "high"]}},
        ],
    }

    hint = dsl.findings_filter_hint(condition)

    assert hint == {
        "filter[severity__in]": ["critical", "high"],
        "filter[check_id__in]": ["a"],
    }
    assert dsl.condition_from_filter_bag(hint)["filter"] == {
        "severity": ["critical", "high"],
        "check_id": ["a"],
    }
