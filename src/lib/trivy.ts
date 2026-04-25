import { TrivyVulnerability, TrivyResult , TrivyScanResponse } from "../types";

const TRIVY_SERVER_URL = process.env.TRIVY_SERVER_URL ?? 'http://localhost:4954';

// Calls the Trivy server Twirp JSON API.
// Start the server with: trivy server --listen 0.0.0.0:4954
export async function scanImage(image: string): Promise<TrivyResult[]> {
  const response = await fetch(
    `${TRIVY_SERVER_URL}/twirp/trivy.scanner.v1.Scanner/Scan`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: image,
        artifact_type: 'ARTIFACT_TYPE_CONTAINER_IMAGE',
        options: {},
      }),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Trivy server responded ${response.status}: ${text}`);
  }

  const data = (await response.json()) as TrivyScanResponse;
  return data.Results ?? [];
}
