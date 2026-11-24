import type { FindingTriageDisabledReason } from "@/types/findings-triage";

interface FindingTriageAdapterOptions {
  canEdit: boolean;
  disabledReason?: FindingTriageDisabledReason;
}

// Triage is served by the API in every deployment, Local Server included. The
// API still enforces who may change it (Manage Scans).
export function getFindingTriageAdapterOptions(): FindingTriageAdapterOptions {
  return { canEdit: true };
}
