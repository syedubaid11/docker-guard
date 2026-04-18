import { Router, Request, Response } from 'express';
import type { Image } from '../types';

const scanRouter = Router();

scanRouter.post('/', (req: Request, res: Response) => {
   const image = req.body as Partial<Image>;

   if (!image.name || !image.body || typeof image.body !== 'object') {
      return res.status(400).json({
         message: 'name and body are required',
      });
   }

   return res.status(202).json({
      message: 'scan request received',
      image: {
         name: image.name,
      },
      status: 'queued',
   });
});

export default scanRouter;
