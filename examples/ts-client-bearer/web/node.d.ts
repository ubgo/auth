// The few Node APIs these two programs call, declared here so the example
// type-checks with no npm install (the repository's `task ts:check` runs a
// bare tsc). An app with @types/node installed deletes this file and gets
// the real, complete declarations; every signature below is a subset of them.

declare const process: {
  readonly argv: readonly string[];
  readonly env: Record<string, string | undefined>;
  exitCode?: number;
};

declare module "node:fs/promises" {
  export function readFile(path: string, encoding: "utf8"): Promise<string>;
  export function writeFile(path: string, data: string, options: { mode: number }): Promise<void>;
  export function rm(path: string, options: { force: boolean }): Promise<void>;
}

declare module "node:http" {
  export interface IncomingMessage {
    readonly url?: string;
    readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  }
  export interface ServerResponse {
    writeHead(status: number, headers: Readonly<Record<string, string>>): this;
    end(body: string): this;
  }
  export interface Server {
    listen(port: number, host: string, ready: () => void): this;
    address(): { port: number } | string | null;
  }
  export function createServer(handle: (req: IncomingMessage, res: ServerResponse) => void): Server;
}
