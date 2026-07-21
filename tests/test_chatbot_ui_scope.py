"""Tests for chatbot UI ownership / injection scope policy."""
from multiagent.agents.ai_agents.chatbot_ui_scope import (
    InjectionPolicy,
    OwnershipClass,
    Reachability,
    ScopePolicy,
    classify_injection_scope,
    classify_reachability,
    registrable_domain,
    same_registrable_domain,
)
from multiagent.agents.ai_agents.chatbot_ui_probe import (
    ChatWidget,
    component_is_injectable,
    ui_warrants_vuln,
)


def test_registrable_domain_strips_subdomain():
    assert registrable_domain("https://www.hubspot.com/") == "hubspot.com"
    assert registrable_domain("https://app.hubspot.com/conversations") == "hubspot.com"
    assert registrable_domain("https://chat.myapp.com") == "myapp.com"
    assert registrable_domain("https://foo.example.co.uk/x") == "example.co.uk"


def test_same_etld1_is_in_scope_even_if_cross_origin():
    """Own LLM on product subdomain must not be skipped for being cross-origin."""
    d = classify_injection_scope(
        "https://www.myapp.com/",
        "https://chat.myapp.com/widget",
        provider="",
    )
    assert d.ownership == OwnershipClass.SAME_SITE.value
    assert d.injection_policy == InjectionPolicy.INJECT.value
    assert d.reason == "same_registrable_domain"
    assert d.reachability == Reachability.CROSS_ORIGIN_FRAME.value
    assert same_registrable_domain(
        "https://www.myapp.com/", "https://chat.myapp.com/widget",
    )


def test_hubspot_iframe_on_hubspot_is_same_site_inject():
    d = classify_injection_scope(
        "https://www.hubspot.com/",
        "https://app.hubspot.com/conversations-visitor/53/threads/utk/",
        provider="HubSpot",
        is_vendor_marker=True,
    )
    assert d.ownership == OwnershipClass.SAME_SITE.value
    assert d.injection_policy == InjectionPolicy.INJECT.value
    # Reachability is a fact; policy is the decision.
    assert d.reachability == Reachability.CROSS_ORIGIN_FRAME.value


def test_hubspot_widget_on_klarna_defaults_to_skip():
    d = classify_injection_scope(
        "https://www.klarna.com/",
        "https://app.hubspot.com/conversations-visitor/1",
        provider="HubSpot",
        is_vendor_marker=True,
    )
    assert d.ownership == OwnershipClass.VENDOR_WIDGET.value
    assert d.injection_policy == InjectionPolicy.SKIP_INJECT.value
    assert d.reason == "vendor_widget_default_skip"


def test_include_thirdparty_overrides_vendor_skip():
    d = classify_injection_scope(
        "https://www.klarna.com/",
        "https://app.hubspot.com/conversations-visitor/1",
        provider="HubSpot",
        is_vendor_marker=True,
        policy=ScopePolicy(include_thirdparty=True),
    )
    assert d.ownership == OwnershipClass.VENDOR_WIDGET.value
    assert d.injection_policy == InjectionPolicy.INJECT.value
    assert d.reason == "vendor_widget_explicitly_authorized"


def test_external_surface_detect_only_until_authorized():
    d = classify_injection_scope(
        "https://www.example.com/",
        "https://assistant.othercorp.io/chat",
    )
    assert d.ownership == OwnershipClass.EXTERNAL.value
    assert d.injection_policy == InjectionPolicy.DETECT_ONLY.value

    d2 = classify_injection_scope(
        "https://www.example.com/",
        "https://assistant.othercorp.io/chat",
        policy=ScopePolicy(authorize_external=True),
    )
    assert d2.injection_policy == InjectionPolicy.INJECT.value


def test_reachability_is_independent_of_policy():
    assert classify_reachability(
        "https://www.klarna.com/",
        "https://widget.intercom.io/x",
    ) == Reachability.CROSS_ORIGIN_FRAME.value
    assert classify_reachability(
        "https://www.klarna.com/",
        "https://www.klarna.com/chat",
    ) == Reachability.SAME_ORIGIN.value


def test_component_injectable_respects_policy_not_origin_alone():
    same_site_iframe = ChatWidget(
        tier="passive_hint",
        scope="app_owned",
        ownership="same_site",
        reachability="cross_origin_frame",
        injection_policy="inject",
        source="iframe",
        frame_url="https://chat.myapp.com/w",
        url="https://www.myapp.com/",
    ).to_dict()
    assert component_is_injectable(same_site_iframe) is True
    assert ui_warrants_vuln([same_site_iframe]) is True

    vendor = ChatWidget(
        tier="passive_hint",
        scope="third_party",
        ownership="vendor_widget",
        reachability="cross_origin_frame",
        injection_policy="skip_inject",
        source="iframe",
        frame_url="https://app.hubspot.com/conversations",
        provider="HubSpot",
        url="https://www.klarna.com/",
    ).to_dict()
    assert component_is_injectable(vendor) is False
    assert ui_warrants_vuln([vendor]) is False

    vendor_auth = dict(vendor)
    vendor_auth["injection_policy"] = "inject"
    assert component_is_injectable(vendor_auth) is True
