// Copyright (c), CommunityLogiq Software

import * as drive from '../api/drive';
import {
  BearerTokenContext,
  Environment,
  Region,
} from '../bearer_token_context';
import { RequestContext } from '../request_context';
import { ObjectIdT as ObjectId } from '../types/generated/object-id';

const PATH = '/v1/api/ulv2/drive/file/1234';

/** A context without its own `getStream`. */
class BufferedContext extends RequestContext {
  paths: string[] = [];

  async get(path: string): Promise<Uint8Array> {
    this.paths.push(path);
    return new Uint8Array([1, 2, 3]);
  }

  async post(): Promise<Uint8Array> {
    throw new Error('not implemented');
  }

  async put(): Promise<Uint8Array> {
    throw new Error('not implemented');
  }

  async delete(): Promise<Uint8Array> {
    throw new Error('not implemented');
  }

  async upload(): Promise<Uint8Array> {
    throw new Error('not implemented');
  }
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<number[]> {
  const bytes: number[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return bytes;
    }
    bytes.push(...value);
  }
}

function context(): BearerTokenContext {
  return new BearerTokenContext('token', Region.CA, Environment.Stage);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('getStream', () => {
  it('reads the complete body by default', async () => {
    const ctx = new BufferedContext();

    const stream = await drive.getFileStream(ctx, new ObjectId());

    expect(await readAll(stream)).toEqual([1, 2, 3]);
    expect(ctx.paths).toHaveLength(1);
    expect(ctx.paths[0]).toMatch(/^\/v1\/api\/ulv2\/drive\/file\//);
  });

  it('gives the body in parts', async () => {
    let sendRest: () => void = () => {};
    const readFirst = new Promise<void>(resolve => {
      sendRest = resolve;
    });
    const body = new ReadableStream<Uint8Array>({
      async start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        // A context that reads the complete body first never gets here.
        await readFirst;
        controller.enqueue(new Uint8Array([3]));
        controller.close();
      },
    });
    const fetch = vi.fn(async () => new Response(body));
    vi.stubGlobal('fetch', fetch);

    const stream = await context().getStream(PATH, [['a', 'b c']], {});
    const reader = stream.getReader();
    const first = await reader.read();
    sendRest();
    const rest = await reader.read();
    const end = await reader.read();

    expect([...first.value!]).toEqual([1, 2]);
    expect([...rest.value!]).toEqual([3]);
    expect(end.done).toBe(true);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`https://stage.urbanlogiq.ca${PATH}?a=b%20c`);
    expect(init.method).toBe('GET');
    expect(init.headers).toEqual({ Authorization: 'Bearer token' });
  });

  it('gives an empty stream for a response without content', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 204 }))
    );

    const stream = await context().getStream(PATH, [], {});

    expect(await readAll(stream)).toEqual([]);
  });

  it('fails with the body of an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('no such file', { status: 404 }))
    );

    await expect(context().getStream(PATH, [], {})).rejects.toThrow(
      /404: no such file/
    );
  });
});
