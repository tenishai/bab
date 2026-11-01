import pytest

from bab.catalogue import Catalogue, CatalogueError, load


def test_loads_example_profile():
    cat = load("catalogues/example.yaml")
    assert cat.resources == ("project", "cluster", "namespace")
    assert cat.action("pod_delete").tier == "mutate"
    assert cat.action("log_read").global_ is True
    assert cat.action("log_read").label == ""  # no label: a console shows the name
    assert cat.action("nope") is None


def test_an_action_may_carry_a_label():
    cat = Catalogue.from_dict({"resources": ["room"], "actions": [
        {"name": "github_pulls_review", "tier": "mutate", "vendor": "github", "label": "Review pull requests"},
        {"name": "github_repos_read", "tier": "read", "vendor": "github", "label": None}]})
    assert cat.action("github_pulls_review").label == "Review pull requests"
    assert cat.action("github_repos_read").label == ""


@pytest.mark.parametrize("raw,msg", [
    ({"resources": []}, "at least one level"),
    ({"resources": ["project"], "actions": [{"name": "Pod-Delete", "tier": "mutate"}]}, "bad action name"),
    ({"resources": ["project"], "actions": [{"name": "approver", "tier": "read"}]}, "bad action name"),
    ({"resources": ["project"], "actions": [{"name": "x_gated", "tier": "read"}]}, "collides"),
    ({"resources": ["project"], "actions": [{"name": "x", "tier": "yolo"}]}, "tier must be"),
    ({"resources": ["project"], "actions": [{"name": "x", "tier": "read"}] * 2}, "duplicate action"),
    ({"resources": ["project", "project"]}, "duplicate resource"),
])
def test_rejects_bad_catalogues(raw, msg):
    with pytest.raises(CatalogueError, match=msg):
        Catalogue.from_dict(raw)


def test_vendors_have_a_kind_and_a_default():
    from bab.catalogue import Catalogue, CatalogueError

    cat = Catalogue.from_dict({"resources": ["room"], "vendors": {"aws": {"kind": "cloud", "label": "AWS", "account": "account"}},
                               "actions": [{"name": "aws_s3_read", "tier": "read", "vendor": "aws"},
                                           {"name": "pagerduty_incidents_read", "tier": "read", "vendor": "pagerduty"}]})
    assert cat.vendor("aws").kind == "cloud" and cat.vendor("aws").account == "account"
    assert cat.vendor("pagerduty").kind == "service" and cat.vendor("pagerduty").label == "pagerduty"
    assert cat.vendor_names() == ("aws", "pagerduty")
    import pytest

    with pytest.raises(CatalogueError, match="kind"):
        Catalogue.from_dict({"resources": ["room"], "vendors": {"x": {"kind": "planet"}}})
