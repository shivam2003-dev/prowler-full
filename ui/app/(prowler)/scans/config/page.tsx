import { SlidersVertical } from "lucide-react";

import { getProviders } from "@/actions/providers";
import { listScanConfigurations } from "@/actions/scan-configurations";
import { ContentLayout } from "@/components/shadcn/content-layout";

import { ScanConfigurationsManager } from "./_components/scan-configurations-manager";

export default async function ScanConfigPage() {
  // A failure here propagates to the `(prowler)/error.tsx` boundary instead of
  // rendering a false "no scan configurations" empty table during SSR.
  const [configs, providersResponse] = await Promise.all([
    listScanConfigurations(),
    getProviders({ pageSize: 100 }),
  ]);

  if (!providersResponse) {
    throw new Error("Failed to load Providers for Scan Configuration.");
  }

  const richProviders = providersResponse.data;

  return (
    <ContentLayout title="Configuration" icon={<SlidersVertical />}>
      <ScanConfigurationsManager
        initialConfigs={configs}
        richProviders={richProviders}
      />
    </ContentLayout>
  );
}
