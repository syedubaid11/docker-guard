import { Router, Request, Response } from 'express';
import type { Image } from '../types';
import { exec } from 'child_process';

const scanRouter = Router();

const TRIVY_SERVER_URL = process.env.TRIVY_SERVER_URL || 'http://localhost:4954';

scanRouter.post('/', (req: Request, res: Response) => {
   const image = req.body as Partial<Image>;

   if (!image.name) {
      return res.status(400).json({
         message: 'name is required',
      });
   }

   const command = `trivy image --server ${TRIVY_SERVER_URL} --format json ${image.name}`;

   exec(command, (error, stdout, stderr) => {
      if (error) {
         return res.status(500).json({
            message: 'scan failed',
            error: stderr,
         });
      }

      try {
         const results = JSON.parse(stdout);
         return res.status(200).json({
            message: 'scan complete',
            image: { name: image.name },
            results,
         });
      } catch (e) {
         return res.status(500).json({
            message: 'failed to parse trivy output',
            raw: stdout,
         });
      }
   });
});

export default scanRouter;
