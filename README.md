# @cap/decrypt-bundle

Native plugin to securely decrypt encrypted exam bundles and return local file paths for rendering.

## Install

To use npm

```bash
npm install @cap/decrypt-bundle
````

To use yarn

```bash
yarn add @cap/decrypt-bundle
```

Sync native files

```bash
npx cap sync
```

## API

<docgen-index>

* [`decrypt(...)`](#decrypt)
* [Interfaces](#interfaces)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### decrypt(...)

```typescript
decrypt(options: DecryptBundleOptions) => Promise<DecryptBundleResult>
```

| Param         | Type                                                                  |
| ------------- | --------------------------------------------------------------------- |
| **`options`** | <code><a href="#decryptbundleoptions">DecryptBundleOptions</a></code> |

**Returns:** <code>Promise&lt;<a href="#decryptbundleresult">DecryptBundleResult</a>&gt;</code>

--------------------


### Interfaces


#### DecryptBundleResult

| Prop       | Type                |
| ---------- | ------------------- |
| **`path`** | <code>string</code> |


#### DecryptBundleOptions

| Prop               | Type                |
| ------------------ | ------------------- |
| **`assessmentId`** | <code>string</code> |
| **`cek`**          | <code>string</code> |
| **`iv`**           | <code>string</code> |
| **`tag`**          | <code>string</code> |
| **`examId`**       | <code>string</code> |
| **`sessionId`**    | <code>string</code> |

</docgen-api>
