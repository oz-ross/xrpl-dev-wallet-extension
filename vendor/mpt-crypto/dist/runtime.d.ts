import { Marshaller } from './marshal';
import { WasmModule } from './module';
/**
 * Load the (cached) WASM module, run `fn` with a fresh {@link Marshaller}, and
 * release every scratch allocation afterwards. All high-level API functions go
 * through this helper so they never leak WASM heap memory, even on error.
 *
 * @param fn - Callback receiving the loaded module and a bound marshaller.
 * @returns The value returned by `fn`.
 */
export declare function withModule<T>(fn: (mod: WasmModule, marshaller: Marshaller) => T): Promise<T>;
