import { Radar } from "lucide-react";
import { Suspense } from "react";

import { RealtimeDashboard } from "@/app/(prowler)/realtime/_components/dashboard/realtime-dashboard";
import { RealtimeDashboardSkeleton } from "@/app/(prowler)/realtime/_components/dashboard/realtime-dashboard-skeleton";
import type { RealtimeSearchParams } from "@/app/(prowler)/realtime/_lib/routes";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface RealtimePageProps {
  searchParams: Promise<RealtimeSearchParams>;
}

export default async function RealtimePage({
  searchParams,
}: RealtimePageProps) {
  const params = await searchParams;

  return (
    <ContentLayout title="Realtime" icon={<Radar />}>
      <Suspense fallback={<RealtimeDashboardSkeleton />}>
        <RealtimeDashboard searchParams={params} />
      </Suspense>
    </ContentLayout>
  );
}
