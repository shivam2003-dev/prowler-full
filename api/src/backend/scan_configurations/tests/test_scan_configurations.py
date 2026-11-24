import pytest
from api.models import ScanConfiguration
from api.utils import get_scan_config_content
from django.urls import reverse
from rest_framework import status

CONTENT_TYPE = "application/vnd.api+json"
CONFIG = {"aws": {"max_unused_access_keys_days": 30}, "azure": {"shodan_api_key": None}}


def _payload(config_id=None, **attributes):
    data = {"type": "scan-configurations", "attributes": attributes}
    if config_id:
        data["id"] = config_id
    return {"data": data}


def _create(client, **attributes):
    attributes = {"name": "Strict", "configuration": CONFIG, **attributes}
    return client.post(
        reverse("scan-configuration-list"),
        data=_payload(**attributes),
        content_type=CONTENT_TYPE,
    )


def _patch(client, config_id, **attributes):
    return client.patch(
        reverse("scan-configuration-detail", kwargs={"pk": config_id}),
        data=_payload(config_id, **attributes),
        content_type=CONTENT_TYPE,
    )


@pytest.mark.django_db
class TestScanConfigurationViewSet:
    def test_create_attaches_providers(self, authenticated_client, aws_provider):
        response = _create(authenticated_client, provider_ids=[str(aws_provider.id)])

        assert response.status_code == status.HTTP_201_CREATED, response.json()
        attributes = response.json()["data"]["attributes"]
        assert attributes["name"] == "Strict"
        assert attributes["configuration"] == CONFIG
        assert attributes["providers"] == [str(aws_provider.id)]

    def test_create_accepts_yaml_string(self, authenticated_client):
        response = _create(
            authenticated_client,
            configuration="aws:\n  max_unused_access_keys_days: 30\n",
        )

        assert response.status_code == status.HTTP_201_CREATED, response.json()
        assert response.json()["data"]["attributes"]["configuration"] == {
            "aws": {"max_unused_access_keys_days": 30}
        }

    @pytest.mark.parametrize(
        "configuration",
        [{}, [], "just text", {"not_a_provider": {}}, {"aws": "nope"}, "aws: [1, 2"],
    )
    def test_create_rejects_invalid_configuration(
        self, authenticated_client, configuration
    ):
        response = _create(authenticated_client, configuration=configuration)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["source"]["pointer"] == (
            "/data/attributes/configuration"
        )
        assert not ScanConfiguration.objects.exists()

    def test_create_rejects_duplicate_name_and_unknown_provider(
        self, authenticated_client
    ):
        _create(authenticated_client)

        duplicate = _create(authenticated_client)
        unknown = _create(
            authenticated_client,
            name="Other",
            provider_ids=["00000000-0000-4000-8000-000000000000"],
        )

        assert duplicate.status_code == status.HTTP_400_BAD_REQUEST
        assert unknown.status_code == status.HTTP_400_BAD_REQUEST
        assert unknown.json()["errors"][0]["source"]["pointer"] == (
            "/data/attributes/provider_ids"
        )
        assert ScanConfiguration.objects.count() == 1

    def test_attaching_a_provider_moves_it_off_the_other_configuration(
        self, authenticated_client, aws_provider
    ):
        first = _create(authenticated_client, provider_ids=[str(aws_provider.id)])
        second = _create(authenticated_client, name="Relaxed")

        response = _patch(
            authenticated_client,
            second.json()["data"]["id"],
            provider_ids=[str(aws_provider.id)],
        )

        assert response.status_code == status.HTTP_200_OK, response.json()
        assert response.json()["data"]["attributes"]["providers"] == [
            str(aws_provider.id)
        ]
        # A provider_ids-only PATCH leaves name and configuration alone.
        assert response.json()["data"]["attributes"]["name"] == "Relaxed"
        first_detail = authenticated_client.get(
            reverse(
                "scan-configuration-detail", kwargs={"pk": first.json()["data"]["id"]}
            )
        )
        assert first_detail.json()["data"]["attributes"]["providers"] == []

    def test_empty_provider_ids_detaches_all(self, authenticated_client, aws_provider):
        created = _create(authenticated_client, provider_ids=[str(aws_provider.id)])

        response = _patch(
            authenticated_client, created.json()["data"]["id"], provider_ids=[]
        )

        assert response.json()["data"]["attributes"]["providers"] == []

    def test_list_and_delete(self, authenticated_client):
        created = _create(authenticated_client)

        listed = authenticated_client.get(reverse("scan-configuration-list"))
        deleted = authenticated_client.delete(
            reverse(
                "scan-configuration-detail",
                kwargs={"pk": created.json()["data"]["id"]},
            )
        )

        assert len(listed.json()["data"]) == 1
        assert deleted.status_code == status.HTTP_204_NO_CONTENT
        assert not ScanConfiguration.objects.exists()

    def test_requires_manage_scans(self, authenticated_client_no_permissions_rbac):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("scan-configuration-list")
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestGetScanConfigContent:
    def test_returns_the_section_of_the_provider_type(
        self, authenticated_client, aws_provider
    ):
        _create(authenticated_client, provider_ids=[str(aws_provider.id)])

        assert get_scan_config_content(aws_provider) == {
            "max_unused_access_keys_days": 30
        }

    def test_none_without_configuration(self, aws_provider):
        assert get_scan_config_content(aws_provider) is None

    def test_none_when_configuration_has_no_section_for_the_type(
        self, authenticated_client, aws_provider
    ):
        _create(
            authenticated_client,
            configuration={"gcp": {"shodan_api_key": None}},
            provider_ids=[str(aws_provider.id)],
        )

        assert get_scan_config_content(aws_provider) is None
