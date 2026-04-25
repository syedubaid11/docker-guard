import { Queue } from 'bullmq';
import { redis } from '../lib/redis';
import type { ScanJobData } from '../types';

export const scanQueue = new Queue<ScanJobData>('docker-scans', {
  connection: redis,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
  },
});
