import { WebPlugin } from '@capacitor/core';

import type {
  DecryptBundleOptions,
  DecryptBundlePlugin,
  DecryptBundleResult,
} from './definitions';

export class DecryptBundleWeb extends WebPlugin implements DecryptBundlePlugin {
  async decrypt(
    _options: DecryptBundleOptions,
  ): Promise<DecryptBundleResult> {
    throw this.unimplemented(
      'DecryptBundle.decrypt is only available on Android and iOS.',
    );
  }
}
