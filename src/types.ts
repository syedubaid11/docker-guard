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

export type Image = {
    body: object;
    name: string;
}
