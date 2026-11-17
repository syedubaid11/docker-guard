const AI_ENGINE_URL = process.env.AI_ENGINE_URL ?? 'http://localhost:8000';

export type Risk = { risk: number; reasons: string[] };

type VulnInput = {
  vulnerabilityId: string;
  cvssVector: string | null;
  cvssScore: number | null;
  cweIds: string[];
  publishedDate: Date | null;
  description: string | null;
};

// Asks the AI engine for each vulnerability's exploit risk. Returns one entry per input (same order),
// null where there is no score. Never throws: if the engine is down the scan is still saved, unscored.
export async function predictRisk(vulns: VulnInput[]): Promise<(Risk | null)[]> {
  const out: (Risk | null)[] = vulns.map(() => null);
  // The model was trained only on CVEs with a CVSS v3 vector, so only those get a score.
  const scored = vulns.flatMap((v, i) => (v.cvssVector ? [i] : []));
  if (scored.length === 0) return out;

  try {
    const res = await fetch(`${AI_ENGINE_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(
        scored.map((i) => ({
          id: vulns[i].vulnerabilityId,
          vector: vulns[i].cvssVector,
          score: vulns[i].cvssScore,
          cwes: vulns[i].cweIds,
          published: vulns[i].publishedDate?.toISOString() ?? null,
          description: vulns[i].description,
        }))
      ),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`AI engine returned HTTP ${res.status}`);
    const risks = (await res.json()) as Risk[];
    risks.forEach((r, k) => (out[scored[k]] = { risk: r.risk, reasons: r.reasons }));
  } catch (err) {
    console.error('risk prediction skipped:', err);
  }
  return out;
}
