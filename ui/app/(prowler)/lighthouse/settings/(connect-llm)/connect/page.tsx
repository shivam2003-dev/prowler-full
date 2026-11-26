import { redirect } from "next/navigation";

import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

// LLM providers are connected from the Lighthouse AI settings page; this
// legacy step is kept only so old links land somewhere useful.
export default function ConnectLLMProviderPage() {
  redirect(LIGHTHOUSE_ROUTE.SETTINGS);
}
