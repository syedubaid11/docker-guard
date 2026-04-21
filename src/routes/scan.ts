import { Router, Request, Response } from 'express';
import { prisma } from '../lib/prisma';
import { scanQueue } from '../queues/scanQueue';

const router = Router();

// Basic Docker image reference validation: allows registry/name:tag@digest forms
const IMAGE_REF_RE = /^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$/;

router.post('/', async (req: Request, res: Response) => {
  const { image } = req.body as { image?: string };

  if (!image || !IMAGE_REF_RE.test(image)) {
    res.status(400).json({ error: 'Invalid or missing image reference' });
    return;
  }

  const scan = await prisma.scan.create({
    data: { image, status: 'PENDING' },
  });

  const job = await scanQueue.add('scan', { scanId: scan.id, image });

  await prisma.scan.update({
    where: { id: scan.id },
    data: { jobId: job.id! },
  });

  res.status(202).json({ scanId: scan.id, jobId: job.id, status: 'PENDING' });
});

router.get('/:scanId', async (req: Request, res: Response) => {
  const scanId = req.params['scanId'] as string;

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: { vulnerabilities: true },
  });

  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  res.json(scan);
});

export default router;
