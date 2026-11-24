import {
  getLighthouseV2Configurations,
  getLighthouseV2SupportedProviders,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2ConfigPage } from "@/app/(prowler)/lighthouse/_components/config";
import { ContentLayout } from "@/components/shadcn/content-layout";

export const dynamic = "force-dynamic";

export default async function LighthouseSettingsPage() {
  const [configurationsResult, providersResult] = await Promise.all([
    getLighthouseV2Configurations(),
    getLighthouseV2SupportedProviders(),
  ]);

  const providers = "data" in providersResult ? providersResult.data : [];
  const error =
    "error" in configurationsResult
      ? configurationsResult.error
      : "error" in providersResult
        ? providersResult.error
        : undefined;

  return (
    <ContentLayout title="Settings">
      <LighthouseV2ConfigPage
        configurations={
          "data" in configurationsResult ? configurationsResult.data : []
        }
        providers={providers}
        error={error}
      />
    </ContentLayout>
  );
}
