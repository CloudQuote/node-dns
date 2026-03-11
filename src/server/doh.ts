import * as http from 'node:http';
import * as https from 'node:https';
import { EventEmitter } from 'node:events';
import { debuglog } from 'node:util';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ServerOptions as HttpsServerOptions } from 'node:https';

import Packet from '../packet.ts';

const debug = debuglog('dns2-server');

export type CorsOption = boolean | string | ((origin?: string) => boolean);

export interface DohServerOptions extends HttpsServerOptions {
  cors?: CorsOption;
  ssl?: boolean;
  port?: number;
}

const decodeBase64URL = (value: string): string | undefined => {
  let queryData = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = queryData.length % 4;
  if (pad === 1) {
    return undefined;
  }
  if (pad) {
    queryData += '='.repeat(4 - pad);
  }
  return queryData;
};

const readStream = (stream: NodeJS.ReadableStream): Promise<Buffer> => new Promise((resolve, reject) => {
  const chunks: Buffer[] = [];
  stream
    .on('error', reject)
    .on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)))
    .on('end', () => resolve(Buffer.concat(chunks)));
});

export default class Server extends EventEmitter {
  cors: CorsOption;
  port?: number;
  server: http.Server | https.Server;

  constructor(options: DohServerOptions = {}) {
    super();
    const merged: DohServerOptions & { cors: CorsOption } = Object.assign({ cors: true }, options);
    this.cors = merged.cors ?? true;
    this.port = merged.port;
    this.server = (merged.ssl ? https.createServer(merged) : http.createServer())
      .on('request', this.handleRequest.bind(this))
      .on('listening', () => this.emit('listening', this.address()))
      .on('error', error => this.emit('error', error))
      .on('close', () => {
        this.server.removeAllListeners();
        this.emit('close');
      });
  }

  async handleRequest(client: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      const { method, url = '/', headers } = client;
      const { pathname, searchParams } = new URL(url, 'http://unused/');

      if (this.cors === true) {
        response.setHeader('Access-Control-Allow-Origin', '*');
      } else if (typeof this.cors === 'string') {
        response.setHeader('Access-Control-Allow-Origin', this.cors);
        response.setHeader('Vary', 'Origin');
      } else if (typeof this.cors === 'function') {
        const isAllowed = this.cors(headers.origin);
        response.setHeader('Access-Control-Allow-Origin', isAllowed ? headers.origin ?? 'false' : 'false');
        response.setHeader('Vary', 'Origin');
      }

      debug('request', method, url);
      if (method !== 'GET' && method !== 'POST') {
        response.writeHead(405, { 'Content-Type': 'text/plain' });
        response.end('405 Method not allowed\n');
        return;
      }

      if (pathname !== '/dns-query') {
        response.writeHead(404, { 'Content-Type': 'text/plain' });
        response.end('404 Not Found\n');
        return;
      }

      if (headers.accept !== 'application/dns-message') {
        response.writeHead(400, { 'Content-Type': 'text/plain' });
        response.end('400 Bad Request: Illegal content type\n');
        return;
      }

      let queryData: Buffer;
      if (method === 'GET') {
        const dns = searchParams.get('dns');
        if (!dns) {
          response.writeHead(400, { 'Content-Type': 'text/plain' });
          response.end('400 Bad Request: No query defined\n');
          return;
        }

        const base64 = decodeBase64URL(dns);
        if (!base64) {
          response.writeHead(400, { 'Content-Type': 'text/plain' });
          response.end('400 Bad Request: Invalid query data\n');
          return;
        }

        queryData = Buffer.from(base64, 'base64');
      } else {
        queryData = await readStream(client);
      }

      const message = Packet.parse(queryData);
      this.emit('request', message, this.response.bind(this, response), client);
    } catch (error) {
      this.emit('requestError', error);
      response.destroy();
    }
  }

  response(response: ServerResponse, message: Packet): void {
    debug('response');
    response.setHeader('Content-Type', 'application/dns-message');
    response.writeHead(200);
    response.end(message.toBuffer());
  }

  listen(port?: number, address?: string): http.Server | https.Server {
    return this.server.listen(port ?? this.port, address);
  }

  address(): ReturnType<http.Server['address']> {
    return this.server.address();
  }

  close(): http.Server | https.Server {
    return this.server.close();
  }
}
