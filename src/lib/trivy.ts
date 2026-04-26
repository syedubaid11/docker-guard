import { execFile } from 'child_process';
import { promisify } from 'util';
import type { TrivyResult, TrivyScanResponse } from '../types';

const execFileP = promisify(execFile);

const TRIVY_SERVER_URL = process.env.TRIVY_SERVER_URL ?? 'http://localhost:4954';
const TRIVY_BIN = process.env.TRIVY_BIN ?? 'trivy';

// Runs the Trivy CLI in client/server mode against the running Trivy server.
// `execFile` passes args as an array (no shell), so the image string is safe
// from command injection.
export async function scanImage(image: string): Promise<TrivyResult[]> {
  const args = [
    'image',
    '--server', TRIVY_SERVER_URL,
    '--format', 'json',
    '--quiet',
    '--scanners', 'vuln',
    image,
  ];

  const { stdout } = await execFileP(TRIVY_BIN, args, {
    maxBuffer: 50 * 1024 * 1024, // 50 MB — Trivy JSON can be big
    timeout: 5 * 60 * 1000,      // 5 min
  });

  const data = JSON.parse(stdout) as TrivyScanResponse;
  return data.Results ?? [];
}
