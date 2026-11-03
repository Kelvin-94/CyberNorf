/* global process */
/**
 * Point git at the versioned hooks in `.githooks`.
 *
 * Runs from the `prepare` lifecycle script, so a fresh clone gets the
 * protected-branch guard as soon as `npm install` completes.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

if (!existsSync(".git")) {
  process.exit(0);
}

try {
  execFileSync("git", ["rev-parse", "--is-inside-work-tree"], { stdio: "ignore" });
} catch {
  process.exit(0);
}

execFileSync("git", ["config", "core.hooksPath", ".githooks"], { stdio: "ignore" });
