import { decryptAmountBsgs } from '@xrplf/mpt-crypto';

// Runs in a Web Worker — WASM execution blocks this thread, not the main thread.
self.onmessage = async ({ data }) => {
  const { id, ciphertext, privateKey } = data;
  try {
    const result = await decryptAmountBsgs(ciphertext, privateKey);
    // BigInt is structured-cloneable in Chrome; send as string to be safe.
    self.postMessage({ id, result: result.toString() });
  } catch (err) {
    self.postMessage({ id, error: err.message ?? String(err) });
  }
};
