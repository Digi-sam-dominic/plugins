import { WebPlugin } from '@capacitor/core';

import type { DecryptBundlePlugin } from './definitions';

export class DecryptBundleWeb extends WebPlugin implements DecryptBundlePlugin {
  async echo(options: { value: string }): Promise<{ value: string }> {
    console.log('ECHO', options);
    return options;
  }
}
