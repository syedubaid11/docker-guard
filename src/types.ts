import type { AuthPayload } from './middleware/auth';

export interface ScanJobData {
  scanId: string;
  image: string;
}

export type LoginBody = {
  email?: string;
  password?: string;
};

export type SignupBody = {
  name?: string;
  email?: string;
  password?: string;
};

declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}
