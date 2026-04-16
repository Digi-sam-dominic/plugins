export interface DecryptBundlePlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
}
