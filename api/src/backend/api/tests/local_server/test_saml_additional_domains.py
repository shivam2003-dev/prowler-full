import pytest
from api.models import SAMLConfiguration, SAMLDomainIndex
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError


@pytest.mark.django_db
class TestSamlAdditionalDomains:
    def test_additional_domains_are_normalized_and_indexed(self, saml_setup):
        config = SAMLConfiguration.objects.get()

        config.additional_email_domains = [" Acme.io ", "acme.io", "sub.prowler.dev"]
        config.save()

        config.refresh_from_db()
        assert config.additional_email_domains == ["acme.io", "sub.prowler.dev"]
        assert config.allowed_email_domains == {
            "prowler.com",
            "acme.io",
            "sub.prowler.dev",
        }
        indexed = set(SAMLDomainIndex.objects.values_list("email_domain", flat=True))
        assert indexed == {"prowler.com", "acme.io", "sub.prowler.dev"}

    def test_removed_domains_leave_the_index(self, saml_setup):
        config = SAMLConfiguration.objects.get()
        config.additional_email_domains = ["acme.io", "other.io"]
        config.save()

        config.additional_email_domains = ["other.io"]
        config.save()

        indexed = set(SAMLDomainIndex.objects.values_list("email_domain", flat=True))
        assert indexed == {"prowler.com", "other.io"}

    def test_domain_owned_by_another_tenant_is_rejected(
        self, saml_setup, tenants_fixture
    ):
        SAMLDomainIndex.objects.create(
            email_domain="taken.io", tenant_id=tenants_fixture[1].id
        )
        config = SAMLConfiguration.objects.get()
        config.additional_email_domains = ["taken.io"]

        with pytest.raises((ValidationError, DjangoValidationError)):
            config.save()

    @pytest.mark.parametrize("domains", [["prowler.com"], ["user@acme.io"], ["nodot"]])
    def test_invalid_domains_are_rejected(self, saml_setup, domains):
        config = SAMLConfiguration.objects.get()
        config.additional_email_domains = domains

        with pytest.raises((ValidationError, DjangoValidationError)):
            config.save()

    def test_delete_removes_every_domain_from_the_index(self, saml_setup):
        config = SAMLConfiguration.objects.get()
        config.additional_email_domains = ["acme.io"]
        config.save()

        config.delete()

        assert not SAMLDomainIndex.objects.exists()
