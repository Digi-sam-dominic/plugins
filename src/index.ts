import { registerPlugin } from '@capacitor/core';

import type { DecryptBundlePlugin } from './definitions';

const DecryptBundle = registerPlugin<DecryptBundlePlugin>('DecryptBundle', {
  web: () => import('./web').then((m) => new m.DecryptBundleWeb()),
});

export * from './definitions';
export { DecryptBundle };
