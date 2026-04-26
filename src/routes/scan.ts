import { Router, Request, Response } from 'express';
import { prisma } from '../lib/prisma';
import { scanQueue } from '../queues/scanQueue';
import { requireAuth } from '../middleware/auth';

const scanRouter = Router();

// All scan routes require auth.
scanRouter.use(requireAuth);

// Enqueue a scan for the authenticated user. Returns 202 + scanId.
scanRouter.post('/', async (req: Request, res: Response) => {
  const { image } = req.body as { image?: string };
  const userId = req.user!.id;

  if (!image || typeof image !== 'string') {
    return res.status(400).json({ message: 'image is required' });
  }

  if (!/^[a-zA-Z0-9._\-\/:@]+$/.test(image)) {
    return res.status(400).json({ message: 'invalid image reference' });
  }

  try {
    const scan = await prisma.scan.create({ data: { image, userId } });
    const job = await scanQueue.add('scan', { scanId: scan.id, image });
    await prisma.scan.update({
      where: { id: scan.id },
      data: { jobId: job.id ?? null },
    });

    return res.status(202).json({ scanId: scan.id, status: scan.status });
  } catch {
    return res.status(500).json({ message: 'failed to enqueue scan' });
  }
});

// Poll a single scan — only the owner can read it.
scanRouter.get('/:scanId', async (req: Request, res: Response) => {
  const scanId = String(req.params.scanId);
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { vulnerabilities: true },
    });

    if (!scan) return res.status(404).json({ message: 'scan not found' });
    if (scan.userId !== req.user!.id) {
      return res.status(403).json({ message: 'forbidden' });
    }

    return res.status(200).json(scan);
  } catch {
    return res.status(500).json({ message: 'failed to fetch scan' });
  }
});

// List the authenticated user's scans.
scanRouter.get('/', async (req: Request, res: Response) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { userId: req.user!.id },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
    return res.status(200).json(scans);
  } catch {
    return res.status(500).json({ message: 'failed to list scans' });
  }
});

export default scanRouter;
