export interface DecryptBundleOptions {
  assessmentId: string;
  cek: string;
  iv: string;
  tag: string;
  examId: string;
  sessionId: string;
}

export interface DecryptBundleResult {
  path: string;
}

export interface DecryptBundlePlugin {
  decrypt(options: DecryptBundleOptions): Promise<DecryptBundleResult>;
}
