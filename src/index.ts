// src/index.ts
import 'dotenv/config';
import express, { Request, Response } from 'express';
import { prisma } from './lib/prisma';
import { startScanWorker } from './workers/scanWorker';
import authRouter from './routes/auth';
import scanRouter from './routes/scan';

const app = express();
const port = process.env.PORT ?? 3000;

app.use(express.json());

app.use('/api', authRouter);
app.use('/api/scan', scanRouter);

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

startScanWorker();

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
