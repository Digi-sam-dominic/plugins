export interface DecryptBundleOptions {
  assessmentId: string;
  cek: string;
  iv: string;
  tag: string;
  examId: string;
  sessionId: string;
}

export interface DecryptBundleResult {
  /** Relative to `Directory.Data` (Android files dir, iOS Documents) for `@capacitor/filesystem`. */
  path: string;
}

export interface DecryptBundlePlugin {
  decrypt(options: DecryptBundleOptions): Promise<DecryptBundleResult>;
}
