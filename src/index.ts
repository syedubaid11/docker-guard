// src/index.ts
import 'dotenv/config';
import express, { Request, Response } from 'express';
import cors from 'cors';
import { prisma } from './lib/prisma';
import { startScanWorker } from './workers/scanWorker';
import authRouter from './routes/auth';
import scanRouter from './routes/scan';

const app = express();
const port = process.env.PORT ?? 3000;

// Allow: any localhost, anything matching FRONTEND_URL, and any *.vercel.app
const allowedOrigins = (process.env.FRONTEND_URL ?? '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl, server-to-server
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));
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
