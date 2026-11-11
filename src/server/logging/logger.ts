import { redactError, redactString, redactValue } from '@/server/security/redaction';

/**
 * Structured application logging.
 *
 * One JSON object per line on stdout, which is what a container log driver and
 * a collector expect. Fields are stable so a dashboard can group on them:
 *
 *   {"time":"…","level":"error","msg":"request.unhandled_error",
 *    "service":"cybernorf","env":"production","requestId":"…",
 *    "error":{"name":"TypeError","message":"…"}}
 *
 * Two rules make this safe to turn on in production:
 *
 * 1. Every record passes through the same redactor the audit trail uses
 *    (`redactValue`), so a token that reaches a log line — because a provider
 *    echoed it, or because someone logged a whole request body — is replaced
 *    before it is written, not after someone notices.
 * 2. Logging never throws. A broken sink, a circular object or a serialisation
 *    failure degrades to a single redacted fallback line; it must not take down
 *    the request that was being logged.
 *
 * This module is Node-only (it writes to `process.stdout`). It is imported by
 * server code, never by middleware, which runs on the edge runtime.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const LEVELS: readonly LogLevel[] = ['debug', 'info', 'warn', 'error'];

export interface LogFields {
  [key: string]: unknown;
}

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  /** Returns a logger that repeats the given fields on every record. */
  child(bindings: LogFields): Logger;
}

export interface LoggerOptions {
  /** Defaults to `LOG_LEVEL`, then `info`. */
  level?: LogLevel;
  /** Defaults to writing one line to stdout. Tests pass a collector. */
  sink?: (line: string) => void;
  /** Fields present on every record from this logger. */
  bindings?: LogFields;
}

const SERVICE = 'cybernorf';

/** Bounded so a pathological stack cannot dominate a log line. */
const MAX_STACK_LENGTH = 4_000;

export function resolveLogLevel(value: string | undefined, fallback: LogLevel = 'info'): LogLevel {
  if (!value) {
    return fallback;
  }
  const normalised = value.trim().toLowerCase();
  return (LEVELS as readonly string[]).includes(normalised) ? (normalised as LogLevel) : fallback;
}

function defaultSink(line: string): void {
  // A single write keeps the record atomic for a line-oriented collector.
  process.stdout.write(`${line}\n`);
}

function serialiseError(error: Error, includeStack: boolean): LogFields {
  const serialised: LogFields = {
    name: error.name,
    message: redactString(error.message),
  };
  if (includeStack && error.stack) {
    serialised.stack = redactString(error.stack.slice(0, MAX_STACK_LENGTH));
  }
  // Prisma and Node attach useful, non-enumerable detail (error codes); copy
  // only primitives so no object graph bypasses the redactor.
  for (const [key, value] of Object.entries(error as unknown as Record<string, unknown>)) {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      serialised[key] = value;
    }
  }
  return serialised;
}

/**
 * Prepares caller fields for serialisation: `Error` values become objects
 * (their `message`/`stack` are non-enumerable and would otherwise vanish).
 */
function normaliseFields(fields: LogFields, includeStack: boolean): LogFields {
  const output: LogFields = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value instanceof Error) {
      output[key] = serialiseError(value, includeStack);
      continue;
    }
    output[key] = value;
  }
  return output;
}

class StructuredLogger implements Logger {
  private readonly threshold: number;
  private readonly sink: (line: string) => void;
  private readonly bindings: LogFields;

  constructor(options: LoggerOptions = {}, bindings: LogFields = {}) {
    this.threshold = LEVEL_WEIGHT[options.level ?? resolveLogLevel(process.env.LOG_LEVEL)];
    this.sink = options.sink ?? defaultSink;
    this.bindings = { ...(options.bindings ?? {}), ...bindings };
  }

  debug(message: string, fields: LogFields = {}): void {
    this.write('debug', message, fields);
  }

  info(message: string, fields: LogFields = {}): void {
    this.write('info', message, fields);
  }

  warn(message: string, fields: LogFields = {}): void {
    this.write('warn', message, fields);
  }

  error(message: string, fields: LogFields = {}): void {
    this.write('error', message, fields);
  }

  child(bindings: LogFields): Logger {
    return new StructuredLogger(
      { level: this.levelName(), sink: this.sink },
      { ...this.bindings, ...bindings },
    );
  }

  private levelName(): LogLevel {
    return LEVELS.find((level) => LEVEL_WEIGHT[level] === this.threshold) ?? 'info';
  }

  private write(level: LogLevel, message: string, fields: LogFields): void {
    if (LEVEL_WEIGHT[level] < this.threshold) {
      return;
    }

    try {
      const record: LogFields = {
        time: new Date().toISOString(),
        level,
        msg: redactString(message),
        service: SERVICE,
        env: process.env.NODE_ENV ?? 'development',
        ...normaliseFields(this.bindings, false),
        ...normaliseFields(fields, level === 'error'),
      };

      // Redact the assembled record as a whole: this catches credential-shaped
      // strings in values as well as secret-named keys at any depth.
      const safe = redactValue(record);
      this.sink(JSON.stringify(safe));
    } catch (error) {
      // Last resort: never propagate a logging failure into the caller.
      try {
        this.sink(
          JSON.stringify({
            time: new Date().toISOString(),
            level: 'error',
            msg: 'logging.failed',
            service: SERVICE,
            env: process.env.NODE_ENV ?? 'development',
            error: redactError(error),
          }),
        );
      } catch {
        // The sink itself is unusable; dropping the line beats failing the request.
      }
    }
  }
}

/** The application logger. Use `child()` for request- or job-scoped fields. */
export const logger: Logger = new StructuredLogger();

export function createLogger(options: LoggerOptions = {}): Logger {
  return new StructuredLogger(options);
}
