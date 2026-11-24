import { redirect } from "next/navigation";

import { getLighthouseV2Messages } from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2ChatPage } from "@/app/(prowler)/lighthouse/_components/chat";
import {
  LIGHTHOUSE_CHAT_CONFIG_STATUS,
  loadLighthouseChatConfig,
} from "@/app/(prowler)/lighthouse/_lib/load-chat-config";
import { LighthouseIcon } from "@/components/icons/Icons";
import {
  APP_SIDEBAR_MODE,
  AppSidebarModeSync,
} from "@/components/layout/app-sidebar";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

export const dynamic = "force-dynamic";

export default async function AIChatbot({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const initialPrompt =
    typeof params.prompt === "string" ? params.prompt : undefined;
  const activeSessionId =
    typeof params.session === "string" ? params.session : undefined;

  const chatConfigResult = await loadLighthouseChatConfig();
  // Errors and the not-configured case both land on settings, where the
  // user can connect (or fix) a provider.
  if (chatConfigResult.status !== LIGHTHOUSE_CHAT_CONFIG_STATUS.READY) {
    return redirect(LIGHTHOUSE_ROUTE.SETTINGS);
  }
  const { config, modelsError } = chatConfigResult;

  const initialMessages = activeSessionId
    ? await getLighthouseV2Messages(activeSessionId)
    : { data: [] };
  // Treat the ?session= id as valid when its messages load (you can't fetch
  // messages for a non-existent session, so this is the authoritative
  // "session exists" check). A stale/deleted id fails here and is dropped so
  // the client starts fresh instead of sending against a dead session.
  const sessionLoaded = Boolean(activeSessionId) && "data" in initialMessages;
  const validSessionId = sessionLoaded ? activeSessionId : undefined;
  const chatMessages =
    sessionLoaded && "data" in initialMessages ? initialMessages.data : [];
  const chatRouteKey = validSessionId ?? initialPrompt ?? "new";

  return (
    <ContentLayout title="Lighthouse AI" icon={<LighthouseIcon size={32} />}>
      <AppSidebarModeSync mode={APP_SIDEBAR_MODE.CHAT} closeSidePanel />
      {/* [contain:layout] traps streamdown's fixed fullscreen overlay inside
            the chat area so it never covers the sidebar or navbar. */}
      <div className="h-[calc(100dvh-6.5rem)] min-h-0 [contain:layout]">
        <LighthouseV2ChatPage
          key={chatRouteKey}
          configurations={config.configurations}
          modelsByProvider={config.modelsByProvider}
          supportedProviders={config.supportedProviders}
          initialSessionId={validSessionId}
          initialMessages={chatMessages}
          initialPrompt={initialPrompt}
          initialError={modelsError}
        />
      </div>
    </ContentLayout>
  );
}
