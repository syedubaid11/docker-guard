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


//////////// ------------ TRIVY ---------------- //////////////////////////////

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  // Keyed by data source ("nvd", "redhat", "ghsa", ...).
  CVSS?: Record<string, { V3Vector?: string; V3Score?: number }>;
  CweIDs?: string[];
  PublishedDate?: string;
}

export interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
}

export interface TrivyScanResponse {
  Results?: TrivyResult[];
}