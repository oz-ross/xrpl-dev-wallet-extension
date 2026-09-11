"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.withModule = withModule;
const marshal_1 = require("./marshal");
const module_1 = require("./module");
/**
 * Load the (cached) WASM module, run `fn` with a fresh {@link Marshaller}, and
 * release every scratch allocation afterwards. All high-level API functions go
 * through this helper so they never leak WASM heap memory, even on error.
 *
 * @param fn - Callback receiving the loaded module and a bound marshaller.
 * @returns The value returned by `fn`.
 */
// eslint-disable-next-line import/prefer-default-export -- the package's internal execution helper; named for call-site clarity
async function withModule(fn) {
    const mod = await (0, module_1.loadWasmModule)();
    const marshaller = new marshal_1.Marshaller(mod);
    try {
        return fn(mod, marshaller);
    }
    finally {
        marshaller.dispose();
    }
}
//# sourceMappingURL=runtime.js.map