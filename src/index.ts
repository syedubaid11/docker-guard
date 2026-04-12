// src/index.ts
import express, { Request, Response } from 'express';

const app = express();
const port = 3000;

app.get('/', (req: Request, res: Response) => {
  res.send('Hello from TypeScript Express!');
});

app.post('/api/scan',(req: Request, res: Response) => {
  // we will first scan the image if it's the correct format or not only then we will proceeed , also add auth maybe in the future to this?
  res.send('Scan request received');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
