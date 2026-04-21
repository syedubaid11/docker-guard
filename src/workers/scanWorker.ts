import { Worker } from 'bullmq';
import { redis } from '../lib/redis';
import { prisma } from '../lib/prisma';
import { scanImage } from '../lib/trivy';
import type { ScanJobData } from '../types';

export function startScanWorker() {
  const worker = new Worker<ScanJobData>(
    'docker-scans',
    async (job) => {
      const { scanId, image } = job.data;

      await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'RUNNING', startedAt: new Date() },
      });

      const results = await scanImage(image);

      const vulnerabilities = results.flatMap((result) =>
        (result.Vulnerabilities ?? []).map((v) => ({
          scanId,
          vulnerabilityId: v.VulnerabilityID,
          pkgName: v.PkgName,
          installedVersion: v.InstalledVersion,
          fixedVersion: v.FixedVersion ?? null,
          severity: v.Severity,
          title: v.Title ?? null,
          description: v.Description ?? null,
        }))
      );

      await prisma.$transaction([
        prisma.vulnerability.createMany({ data: vulnerabilities }),
        prisma.scan.update({
          where: { id: scanId },
          data: { status: 'DONE', completedAt: new Date() },
        }),
      ]);
    },
    {
      connection: redis,
      concurrency: 3, // max concurrent Trivy scans
    }
  );

  worker.on('failed', async (job, err) => {
    if (!job) return;
    await prisma.scan.update({
      where: { id: job.data.scanId },
      data: { status: 'FAILED', errorMessage: err.message },
    });
  });

  return worker;
}
