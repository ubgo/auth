// Runs every OIDC test file: `node test/oidc/run.ts` from clients/ts. Each
// file registers its tests on import; `run` executes them in order.

import "./flow.test.ts";
import "./floors.test.ts";
import "./seams.test.ts";
import "./entries.test.ts";
import "./values.test.ts";
import { run } from "./harness.ts";

await run();
