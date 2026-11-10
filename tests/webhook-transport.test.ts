import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { after, before, test } from 'node:test';
import { sendPinnedPost } from '@/server/security/webhook-transport';

interface Captured {
  host: string | undefined;
  body: string;
  headers: IncomingMessage['headers'];
}

let server: Server;
let captured: Captured;

function start(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<number> {
  server = createServer(handler);
  return new Promise<number>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      resolve(address.port);
    });
  });
}

before(async () => {
  captured = { host: undefined, body: '', headers: {} };
  await start((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      captured.host = request.headers.host;
      captured.headers = request.headers;
      captured.body = Buffer.concat(chunks).toString('utf8');
      response.statusCode = request.url === '/reject' ? 500 : 204;
      response.end();
    });
  });
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

function portOfServer(): number {
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return address.port;
}

test('delivers to the validated address instead of resolving the name again', async () => {
  // `.invalid` is reserved and never resolves, so a successful delivery proves
  // the socket used the pinned address and never looked the name up.
  const port = portOfServer();
  const status = await sendPinnedPost(
    new URL(`http://pinned.invalid:${port}/hook`),
    [{ address: '127.0.0.1', family: 4 }],
    {
      headers: { 'content-type': 'application/json', 'x-test': 'pinned' },
      body: '{"ok":true}',
      timeoutMs: 5_000,
    },
  );

  assert.equal(status, 204);
  assert.equal(captured.body, '{"ok":true}');
  assert.equal(captured.headers['x-test'], 'pinned');
  // The Host header and SNI still come from the URL, so virtual hosting and
  // certificate checks behave as the operator configured them.
  assert.equal(captured.host, `pinned.invalid:${port}`);
});

test('returns a failing status instead of throwing so the caller can retry', async () => {
  const port = portOfServer();
  const status = await sendPinnedPost(new URL(`http://127.0.0.1:${port}/reject`), [], {
    headers: { 'content-type': 'application/json' },
    body: '{}',
    timeoutMs: 5_000,
  });

  assert.equal(status, 500);
});

test('refuses to deliver when no address was validated', async () => {
  // An empty address list means the policy never approved a destination; the
  // name is unresolvable, so delivery must fail rather than fall back to DNS.
  await assert.rejects(
    sendPinnedPost(new URL('http://unresolvable.invalid/hook'), [], {
      headers: { 'content-type': 'application/json' },
      body: '{}',
      timeoutMs: 5_000,
    }),
  );
});

test('gives up when the endpoint does not answer in time', async () => {
  const hanging = createServer(() => {
    // Accept the request and never respond.
  });
  await new Promise<void>((resolve) => hanging.listen(0, '127.0.0.1', resolve));
  const address = hanging.address();
  assert.ok(address && typeof address === 'object');

  try {
    await assert.rejects(
      sendPinnedPost(new URL(`http://127.0.0.1:${address.port}/hang`), [], {
        headers: { 'content-type': 'application/json' },
        body: '{}',
        timeoutMs: 250,
      }),
      /did not answer within 250 ms/,
    );
  } finally {
    await new Promise<void>((resolve) => hanging.close(() => resolve()));
  }
});
