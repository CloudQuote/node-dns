import * as http from 'node:http';
import * as https from 'node:https';
import * as http2 from 'node:http2';
import type { IncomingMessage } from 'node:http';

import Packet, { CLASS } from '../packet.ts';
import type { ResolveFn, ResolveOptions } from './udp.ts';

type DnsMessageResponse = IncomingMessage | {
  headers: Record<string, string | string[] | number | undefined>;
  statusCode?: number;
  on: IncomingMessage['on'];
};

export interface DohClientOptions {
  dns: string;
}

const protocols: Record<string, (
  url: string,
  options: { headers: Record<string, string> },
  done: (response: DnsMessageResponse) => void,
) => { on(event: 'error', listener: (error: Error) => void): unknown } | void> = {
  'http:': http.get,
  'https:': https.get,
  'h2:': (url, options, done) => {
    const urlObject = new URL(url);
    const client = http2.connect(url.replace('h2:', 'https:'));
    const request = client.request({
      ':path': `${urlObject.pathname}${urlObject.search}`,
      ':method': 'GET',
      ...options.headers,
    });

    request.on('response', (headers) => {
      client.close();
      done({
        headers,
        statusCode: headers[':status'],
        on: request.on.bind(request),
      });
    });

    request.on('error', (error) => {
      client.close();
      throw error;
    });

    request.end();
  },
};

const makeRequest = (url: string, query: string): Promise<DnsMessageResponse> => new Promise((resolve, reject) => {
  let target = url;
  const index = target.indexOf('://');
  if (index === -1) {
    target = `https://${target}`;
  }

  // The DNS query is included in a single variable named “dns” in the
  // query component of the request URI.  The value of the “dns” variable
  // is the content of the DNS request message, encoded with base64url
  // [RFC4648](https://datatracker.ietf.org/doc/html/rfc8484#section-4.1).


  const urlObject = new URL(target);
  urlObject.searchParams.set('dns', query);
  const get = protocols[urlObject.protocol];
  if (!get) {
    throw new Error(`Unsupported protocol: ${urlObject.protocol}, must be specified (http://, https:// or h2://)`);
  }

  const request = get(urlObject.toString(), { headers: { accept: 'application/dns-message' } }, resolve);
  if (request) {
    request.on('error', reject);
  }
});

const readStream = (response: DnsMessageResponse): Promise<Buffer> => new Promise((resolve, reject) => {
  const chunks: Buffer[] = [];
  response
    .on('error', reject)
    .on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)))
    .on('end', () => {
      const data = Buffer.concat(chunks);
      if (response.statusCode !== 200) {
        reject(new Error(`HTTP ${response.statusCode}: ${data.toString()}`));
        return;
      }
      resolve(data);
    });
});

const buildQuery = ({
  name,
  type = 'A',
  cls = CLASS.IN,
  clientIp,
  recursive = true,
}: {
  name: string;
  type?: keyof typeof Packet.TYPE;
  cls?: number;
  clientIp?: string;
  recursive?: boolean;
}): string => {
  const packet = new Packet();
  packet.header.rd = recursive ? 1 : 0;

  if (clientIp) {
    packet.additionals.push(new Packet.Resource.EDNS([
      new Packet.Resource.EDNS.ECS(clientIp),
    ]));
  }

  packet.questions.push({ name, class: cls, type: Packet.TYPE[type] });
  return packet.toBase64URL();
};

const DOHClient = ({ dns }: DohClientOptions): ResolveFn => {
  return async (name, type, cls, options: ResolveOptions = {}) => {
    const query = buildQuery({ name, type, cls, ...options });
    const response = await makeRequest(dns, query);
    const data = await readStream(response);
    return Packet.parse(data);
  };
};

export default DOHClient;
