import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { S3IntegrationCard } from "./s3-integration-card";

describe("S3IntegrationCard", () => {
  it("offers Amazon S3 without a Cloud badge on Local Server", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(<S3IntegrationCard />);

    // Then
    expect(screen.queryByText("Cloud")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Manage/ })).toHaveAttribute(
      "href",
      "/integrations/amazon-s3",
    );
  });

  it("shows no Cloud badge in Prowler Cloud", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    render(<S3IntegrationCard />);

    // Then
    expect(screen.queryByText("Cloud")).not.toBeInTheDocument();
  });
});
