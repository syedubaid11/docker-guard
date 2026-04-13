// src/index.ts
import 'dotenv/config';
import express, { Request, Response } from 'express';
import { prisma } from './lib/prisma';

const app = express();
const port = 3000;

app.use(express.json());

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

app.post('/api/scan', (req: Request, res: Response) => {
  // we will first scan the image if it's the correct format or not only then we will proceeed , also add auth maybe in the future to this?
  res.send('Scan request received');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
