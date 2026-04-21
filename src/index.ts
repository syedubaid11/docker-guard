// src/index.ts
import 'dotenv/config';
import express, { Request, Response } from 'express';
import { prisma } from './lib/prisma';
import { startScanWorker } from './workers/scanWorker';
import scanRouter from './routes/scan';

const app = express();
const port = process.env.PORT ?? 3000;

app.use(express.json());

startScanWorker();

app.get('/', (req: Request, res: Response) => {
  res.send('Hello from TypeScript Express!');
});

app.get('/health', async (req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.status(200).json({ status: 'ok', uptime: process.uptime(), db: 'connected' });
  } catch {
    res.status(503).json({ status: 'error', uptime: process.uptime(), db: 'unreachable' });
  }
});

app.use('/api/scan', scanRouter);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});


