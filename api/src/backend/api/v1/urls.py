from alerts.views import (
    AlertRecipientConfirmView,
    AlertRecipientUnsubscribeView,
    AlertRecipientViewSet,
    AlertRuleViewSet,
    AlertSlackChannelViewSet,
)
from allauth.socialaccount.providers.saml.views import ACSView, MetadataView, SLSView
from api.v1.views import (
    AttackPathsScanViewSet,
    ComplianceOverviewViewSet,
    CustomSAMLLoginView,
    CustomTokenObtainView,
    CustomTokenRefreshView,
    CustomTokenSwitchTenantView,
    FindingGroupViewSet,
    FindingViewSet,
    GithubSocialLoginView,
    GoogleSocialLoginView,
    IntegrationJiraViewSet,
    IntegrationViewSet,
    InvitationAcceptViewSet,
    InvitationViewSet,
    LighthouseConfigViewSet,
    LighthouseProviderConfigViewSet,
    LighthouseProviderModelsViewSet,
    LighthouseTenantConfigViewSet,
    MembershipViewSet,
    MuteRuleViewSet,
    OverviewViewSet,
    ProcessorViewSet,
    ProviderGroupProvidersRelationshipView,
    ProviderGroupViewSet,
    ProviderSecretViewSet,
    ProviderViewSet,
    ResourceViewSet,
    RoleProviderGroupRelationshipView,
    RoleViewSet,
    SAMLConfigurationViewSet,
    SAMLInitiateAPIView,
    SAMLTokenValidateView,
    ScanViewSet,
    ScheduleViewSet,
    SchemaView,
    TaskViewSet,
    TenantApiKeyViewSet,
    TenantFinishACSView,
    TenantMembersViewSet,
    TenantViewSet,
    UserRoleRelationshipView,
    UserViewSet,
)
from compliance_watchlist.views import (
    ComplianceWatchlistViewSet,
    CrossProviderComplianceViewSet,
)
from django.http import JsonResponse
from django.urls import include, path, re_path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from drf_spectacular.views import SpectacularRedocView
from ingestions.views import IngestionViewSet
from issues.views import IssueViewSet
from lighthouse.views import (
    LighthouseAIConfigurationViewSet,
    LighthouseSessionEventStreamView,
    LighthouseSessionViewSet,
    LighthouseSupportedProviderViewSet,
)
from realtime.views import RealtimeViewSet
from rest_framework_nested import routers
from scan_configurations.views import ScanConfigurationViewSet
from schedules.views import ScheduleAdvancedViewSet
from triage.views import (
    FindingTriageByUidView,
    FindingTriageNoteView,
    FindingTriageView,
)


# This helper view is used to block any endpoints that should not be available
# To use it, add a new entry in the `urlpatterns` list, for example (old but real one):
#     path(
#         "attack-paths-scans/<uuid:pk>/queries/custom",
#         _blocked_endpoint,
#         name="attack-paths-scans-queries-custom-blocked",
#     ),
@csrf_exempt
def _blocked_endpoint(request, *args, **kwargs):
    return JsonResponse(
        {"errors": [{"detail": "This endpoint is not available."}]},
        status=405,
        content_type="application/vnd.api+json",
    )


router = routers.DefaultRouter(trailing_slash=False)

router.register(r"users", UserViewSet, basename="user")
router.register(r"tenants", TenantViewSet, basename="tenant")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"provider-groups", ProviderGroupViewSet, basename="providergroup")
router.register(r"scans", ScanViewSet, basename="scan")
router.register(
    r"attack-paths-scans", AttackPathsScanViewSet, basename="attack-paths-scans"
)
router.register(r"tasks", TaskViewSet, basename="task")
router.register(r"resources", ResourceViewSet, basename="resource")
router.register(r"findings", FindingViewSet, basename="finding")
router.register(r"finding-groups", FindingGroupViewSet, basename="finding-group")
router.register(r"roles", RoleViewSet, basename="role")
router.register(
    r"compliance-overviews", ComplianceOverviewViewSet, basename="complianceoverview"
)
router.register(r"overviews", OverviewViewSet, basename="overview")
router.register(r"schedules", ScheduleViewSet, basename="schedule")
router.register(r"integrations", IntegrationViewSet, basename="integration")
router.register(r"processors", ProcessorViewSet, basename="processor")
router.register(r"saml-config", SAMLConfigurationViewSet, basename="saml-config")
router.register(
    r"lighthouse-configurations",
    LighthouseConfigViewSet,
    basename="lighthouseconfiguration",
)
router.register(r"api-keys", TenantApiKeyViewSet, basename="api-key")
router.register(
    r"lighthouse/providers",
    LighthouseProviderConfigViewSet,
    basename="lighthouse-providers",
)
router.register(
    r"lighthouse/models",
    LighthouseProviderModelsViewSet,
    basename="lighthouse-models",
)
router.register(r"mute-rules", MuteRuleViewSet, basename="mute-rule")
router.register(
    r"scan-configurations",
    ScanConfigurationViewSet,
    basename="scan-configuration",
)
router.register(r"ingestions", IngestionViewSet, basename="ingestion")
router.register(
    r"lighthouse/config",
    LighthouseAIConfigurationViewSet,
    basename="lighthouse-ai-configuration",
)
router.register(
    r"lighthouse/supported-providers",
    LighthouseSupportedProviderViewSet,
    basename="lighthouse-supported-provider",
)
router.register(
    r"lighthouse/sessions", LighthouseSessionViewSet, basename="lighthouse-session"
)
router.register(r"alerts/rules", AlertRuleViewSet, basename="alert-rule")
router.register(r"alerts/recipients", AlertRecipientViewSet, basename="alert-recipient")
router.register(
    r"alerts/slack-channels",
    AlertSlackChannelViewSet,
    basename="alert-slack-channel",
)

tenants_router = routers.NestedSimpleRouter(router, r"tenants", lookup="tenant")
tenants_router.register(
    r"memberships", TenantMembersViewSet, basename="tenant-membership"
)

users_router = routers.NestedSimpleRouter(router, r"users", lookup="user")
users_router.register(r"memberships", MembershipViewSet, basename="user-membership")

integrations_router = routers.NestedSimpleRouter(
    router, r"integrations", lookup="integration"
)
integrations_router.register(
    r"jira", IntegrationJiraViewSet, basename="integration-jira"
)

urlpatterns = [
    path(
        "realtime/policies",
        RealtimeViewSet.as_view({"get": "list_policies", "post": "create_policy"}),
        name="realtime-policies",
    ),
    path(
        "realtime/policies/<uuid:pk>",
        RealtimeViewSet.as_view({"patch": "update_policy"}),
        name="realtime-policy",
    ),
    path(
        "realtime/frameworks",
        RealtimeViewSet.as_view({"get": "list_frameworks"}),
        name="realtime-frameworks",
    ),
    path(
        "realtime/feeds",
        RealtimeViewSet.as_view({"get": "list_feeds", "post": "create_feed"}),
        name="realtime-feeds",
    ),
    path(
        "realtime/feeds/<uuid:pk>",
        RealtimeViewSet.as_view({"patch": "update_feed"}),
        name="realtime-feed",
    ),
    path(
        "realtime/feeds/<uuid:pk>/poll",
        RealtimeViewSet.as_view({"post": "poll_feed"}),
        name="realtime-feed-poll",
    ),
    path(
        "realtime/events",
        RealtimeViewSet.as_view({"get": "list_events"}),
        name="realtime-events",
    ),
    path(
        "realtime/detections",
        RealtimeViewSet.as_view({"get": "list_detections"}),
        name="realtime-detections",
    ),
    path(
        "realtime/detections/<uuid:pk>",
        RealtimeViewSet.as_view({"get": "retrieve_detection"}),
        name="realtime-detection",
    ),
    path(
        "realtime/actions",
        RealtimeViewSet.as_view({"get": "list_actions"}),
        name="realtime-actions",
    ),
    path(
        "realtime/actions/<uuid:pk>",
        RealtimeViewSet.as_view({"get": "retrieve_action"}),
        name="realtime-action",
    ),
    path(
        "realtime/actions/<uuid:pk>/revert",
        RealtimeViewSet.as_view({"post": "revert_action"}),
        name="realtime-action-revert",
    ),
    path(
        "realtime/credentials",
        RealtimeViewSet.as_view(
            {"get": "list_credentials", "post": "create_credential"}
        ),
        name="realtime-credentials",
    ),
    path(
        "realtime/credentials/<uuid:pk>",
        RealtimeViewSet.as_view({"delete": "delete_credential"}),
        name="realtime-credential",
    ),
    path(
        "realtime/insights/<slug:kind>",
        RealtimeViewSet.as_view({"get": "insight"}),
        name="realtime-insight",
    ),
    path(
        "realtime/notification-targets",
        RealtimeViewSet.as_view({"get": "notification_targets"}),
        name="realtime-notification-targets",
    ),
    path(
        "realtime/remediations",
        RealtimeViewSet.as_view({"get": "list_remediations"}),
        name="realtime-remediations",
    ),
    path(
        "realtime/demo/<slug:kind>",
        RealtimeViewSet.as_view({"get": "demo"}),
        name="realtime-demo",
    ),
    path(
        "schedules",
        ScheduleAdvancedViewSet.as_view({"get": "list_schedules"}),
        name="schedule-advanced-list",
    ),
    path(
        "schedules/bulk",
        ScheduleAdvancedViewSet.as_view({"post": "bulk"}),
        name="schedule-advanced-bulk",
    ),
    path(
        "schedules/<uuid:pk>",
        ScheduleAdvancedViewSet.as_view(
            {
                "get": "retrieve_schedule",
                "patch": "update_schedule",
                "delete": "delete_schedule",
            }
        ),
        name="schedule-advanced-detail",
    ),
    path("issues", IssueViewSet.as_view({"get": "list_issues"}), name="issue-list"),
    path(
        "issues/overview",
        IssueViewSet.as_view({"get": "overview"}),
        name="issue-overview",
    ),
    path(
        "issues/<uuid:pk>",
        IssueViewSet.as_view({"get": "retrieve_issue"}),
        name="issue-detail",
    ),
    path(
        "issues/<uuid:pk>/triage",
        IssueViewSet.as_view({"patch": "update_triage"}),
        name="issue-triage",
    ),
    path(
        "issues/<uuid:pk>/triage/notes",
        IssueViewSet.as_view({"get": "notes", "post": "notes"}),
        name="issue-triage-notes",
    ),
    path(
        "compliance-catalog",
        ComplianceWatchlistViewSet.as_view({"get": "catalog"}),
        name="compliance-catalog",
    ),
    path(
        "compliance-watchlist-entries",
        ComplianceWatchlistViewSet.as_view({"post": "add"}),
        name="compliance-watchlist-entries",
    ),
    path(
        "compliance-watchlist-entries/bulk",
        ComplianceWatchlistViewSet.as_view({"post": "bulk"}),
        name="compliance-watchlist-entries-bulk",
    ),
    path(
        "compliance-watchlist-entries/<uuid:pk>",
        ComplianceWatchlistViewSet.as_view({"delete": "remove"}),
        name="compliance-watchlist-entry",
    ),
    path(
        "findings/<uuid:pk>/compliance-frameworks",
        ComplianceWatchlistViewSet.as_view({"get": "finding_frameworks"}),
        name="finding-compliance-frameworks",
    ),
    path(
        "cross-provider-compliance-overviews/pdf",
        CrossProviderComplianceViewSet.as_view({"post": "pdf_generate"}),
        name="cross-provider-compliance-pdf",
    ),
    path(
        "cross-provider-compliance-overviews/pdf/latest",
        CrossProviderComplianceViewSet.as_view({"get": "pdf_latest"}),
        name="cross-provider-compliance-pdf-latest",
    ),
    path(
        "cross-provider-compliance-overviews/pdf/<uuid:task_id>",
        CrossProviderComplianceViewSet.as_view({"get": "pdf_binary"}),
        name="cross-provider-compliance-pdf-binary",
    ),
    path(
        "cross-account-compliance-overviews/pdf",
        CrossProviderComplianceViewSet.as_view({"post": "cross_account_pdf_generate"}),
        name="cross-account-compliance-pdf",
    ),
    path(
        "cross-account-compliance-overviews/pdf/latest",
        CrossProviderComplianceViewSet.as_view({"get": "cross_account_pdf_latest"}),
        name="cross-account-compliance-pdf-latest",
    ),
    path(
        "cross-account-compliance-overviews/pdf/<uuid:task_id>",
        CrossProviderComplianceViewSet.as_view({"get": "cross_account_pdf_binary"}),
        name="cross-account-compliance-pdf-binary",
    ),
    path(
        "cross-account-compliance-overviews",
        CrossProviderComplianceViewSet.as_view({"get": "cross_account"}),
        name="cross-account-compliance-overview",
    ),
    path(
        "cross-provider-compliance-overviews",
        CrossProviderComplianceViewSet.as_view({"get": "overview"}),
        name="cross-provider-compliance-overview",
    ),
    # Finding uids can contain "/" (ARNs), so they are matched greedily and the
    # literal suffix decides the route. These precede the router's findings/<pk>.
    re_path(
        r"^findings/(?P<finding_uid>.+)/triage/notes/(?P<note_id>[0-9a-f-]{36})$",
        FindingTriageNoteView.as_view(
            {"patch": "update_note", "delete": "delete_note"}
        ),
        name="finding-triage-by-uid-note",
    ),
    re_path(
        r"^findings/(?P<finding_uid>.+)/triage/notes$",
        FindingTriageByUidView.as_view({"get": "list_notes"}),
        name="finding-triage-by-uid-notes",
    ),
    re_path(
        r"^findings/(?P<finding_uid>.+)/triage$",
        FindingTriageByUidView.as_view(
            {"get": "retrieve_triage", "patch": "update_triage"}
        ),
        name="finding-triage-by-uid",
    ),
    path(
        "finding-triages/<uuid:pk>/notes/<uuid:note_id>",
        FindingTriageNoteView.as_view(
            {"patch": "update_note", "delete": "delete_note"}
        ),
        name="finding-triage-note",
    ),
    path(
        "finding-triages/<uuid:pk>/notes",
        FindingTriageView.as_view({"get": "list_notes"}),
        name="finding-triage-notes",
    ),
    path(
        "finding-triages/<uuid:pk>",
        FindingTriageView.as_view({"get": "retrieve_triage", "patch": "update_triage"}),
        name="finding-triage-detail",
    ),
    path(
        "lighthouse/sessions/<uuid:session_id>/event-stream",
        LighthouseSessionEventStreamView.as_view({"get": "list"}),
        name="lighthouse-session-event-stream",
    ),
    path(
        "alerts/recipients/confirm",
        AlertRecipientConfirmView.as_view(),
        name="alert-recipient-confirm",
    ),
    path(
        "alerts/recipients/unsubscribe",
        AlertRecipientUnsubscribeView.as_view(),
        name="alert-recipient-unsubscribe",
    ),
    path("tokens", CustomTokenObtainView.as_view(), name="token-obtain"),
    path("tokens/refresh", CustomTokenRefreshView.as_view(), name="token-refresh"),
    path("tokens/switch", CustomTokenSwitchTenantView.as_view(), name="token-switch"),
    path(
        "providers/secrets",
        ProviderSecretViewSet.as_view({"get": "list", "post": "create"}),
        name="providersecret-list",
    ),
    path(
        "providers/secrets/<uuid:pk>",
        ProviderSecretViewSet.as_view(
            {"get": "retrieve", "patch": "partial_update", "delete": "destroy"}
        ),
        name="providersecret-detail",
    ),
    path(
        "tenants/invitations",
        InvitationViewSet.as_view({"get": "list", "post": "create"}),
        name="invitation-list",
    ),
    path(
        "tenants/invitations/<uuid:pk>",
        InvitationViewSet.as_view(
            {"get": "retrieve", "patch": "partial_update", "delete": "destroy"}
        ),
        name="invitation-detail",
    ),
    path(
        "invitations/accept",
        InvitationAcceptViewSet.as_view({"post": "accept"}),
        name="invitation-accept",
    ),
    path(
        "roles/<uuid:pk>/relationships/provider_groups",
        RoleProviderGroupRelationshipView.as_view(
            {"post": "create", "patch": "partial_update", "delete": "destroy"}
        ),
        name="role-provider-groups-relationship",
    ),
    path(
        "users/<uuid:pk>/relationships/roles",
        UserRoleRelationshipView.as_view(
            {"post": "create", "patch": "partial_update", "delete": "destroy"}
        ),
        name="user-roles-relationship",
    ),
    path(
        "provider-groups/<uuid:pk>/relationships/providers",
        ProviderGroupProvidersRelationshipView.as_view(
            {"post": "create", "patch": "partial_update", "delete": "destroy"}
        ),
        name="provider_group-providers-relationship",
    ),
    path(
        "lighthouse/configuration",
        LighthouseTenantConfigViewSet.as_view(
            {"get": "list", "patch": "partial_update"}
        ),
        name="lighthouse-configurations",
    ),
    # API endpoint to start SAML SSO flow
    path(
        "auth/saml/initiate/", SAMLInitiateAPIView.as_view(), name="api_saml_initiate"
    ),
    path(
        "accounts/saml/<organization_slug>/login/",
        CustomSAMLLoginView.as_view(),
        name="saml_login",
    ),
    path(
        "accounts/saml/<organization_slug>/acs/",
        require_POST(ACSView.as_view()),
        name="saml_acs",
    ),
    path(
        "accounts/saml/<organization_slug>/acs/finish/",
        TenantFinishACSView.as_view(),
        name="saml_finish_acs",
    ),
    path(
        "accounts/saml/<organization_slug>/sls/",
        SLSView.as_view(),
        name="saml_sls",
    ),
    path(
        "accounts/saml/<organization_slug>/metadata/",
        MetadataView.as_view(),
        name="saml_metadata",
    ),
    path("tokens/saml", SAMLTokenValidateView.as_view(), name="token-saml"),
    path("tokens/google", GoogleSocialLoginView.as_view(), name="token-google"),
    path("tokens/github", GithubSocialLoginView.as_view(), name="token-github"),
    path("", include(router.urls)),
    path("", include(tenants_router.urls)),
    path("", include(users_router.urls)),
    path("", include(integrations_router.urls)),
    path("schema", SchemaView.as_view(), name="schema"),
    path("docs", SpectacularRedocView.as_view(url_name="schema"), name="docs"),
]
