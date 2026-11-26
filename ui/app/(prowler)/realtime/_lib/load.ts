import "server-only";

import { getAllProviders } from "@/actions/providers";
import type { RealtimeProviderOption } from "@/app/(prowler)/realtime/_lib/providers";
import type { RealtimeFailure } from "@/app/(prowler)/realtime/_types";
import { auth } from "@/auth.config";
import { isCloud } from "@/lib/shared/env";

export type AwsProvidersResult =
  | { ok: true; providers: RealtimeProviderOption[] }
  | RealtimeFailure;

/**
 * The tenant's AWS providers: Realtime reads CloudTrail and fixes AWS
 * resources, so nothing else is offered. A failed lookup is an error, not
 * "no providers".
 */
export const loadAwsProviders = async (): Promise<AwsProvidersResult> => {
  const response = await getAllProviders();
  if (!response || !Array.isArray(response.data)) {
    return {
      ok: false,
      status: 0,
      error: "Prowler could not load your AWS accounts. Try again.",
    };
  }
  return {
    ok: true,
    providers: response.data
      .filter((provider) => provider.attributes.provider === "aws")
      .map((provider) => ({
        id: provider.id,
        uid: provider.attributes.uid,
        alias: provider.attributes.alias || null,
      })),
  };
};

/**
 * Whether the signed-in role can change Realtime. Prowler Cloud has a dedicated
 * `manage_prowler_realtime` permission; self-hosted roles do not, and the API
 * guards Realtime writes with Manage Scans there.
 */
export const canManageRealtime = async (): Promise<boolean> => {
  const session = await auth();
  const permissions = session?.user?.permissions;
  return isCloud()
    ? Boolean(permissions?.manage_prowler_realtime)
    : Boolean(permissions?.manage_scans);
};
