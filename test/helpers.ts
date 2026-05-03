import { once } from 'node:events';
import * as http from "node:http";
import * as net from "node:net";

import DNS, {
  createDOHServer,
  createServer,
  createTCPServer,
  createUDPServer,
  type DOHServer,
  type DNSServer,
  type TCPServer,
  type UDPServer,
} from '../src/index.ts';
import Packet from '../src/packet.ts';

export const FIXTURES = {
  domain: 'example.test',
  ipv4: '203.0.113.10',
  ipv6: '2001:db8::10',
  alias: 'alias.example.test',
  mail: 'mail.example.test',
  ns: 'ns1.example.test',
  ptr: 'ptr.example.test',
  srv: '_sip._tcp.example.test',
  signer: 'signer.example.test',
};

export const createRichResponse = (request: Packet): Packet => {
  const response = Packet.createResponseFromRequest(request);
  const [question] = response.questions;
  const name = question?.name ?? FIXTURES.domain;
  response.header.ra = 1;

  response.answers.push(
    { name, type: Packet.TYPE.A, class: Packet.CLASS.IN, ttl: 60, address: FIXTURES.ipv4 },
    { name, type: Packet.TYPE.AAAA, class: Packet.CLASS.IN, ttl: 60, address: FIXTURES.ipv6 },
    { name, type: Packet.TYPE.MX, class: Packet.CLASS.IN, ttl: 300, exchange: FIXTURES.mail, priority: 10 },
    { name, type: Packet.TYPE.CNAME, class: Packet.CLASS.IN, ttl: 300, domain: FIXTURES.alias },
    { name, type: Packet.TYPE.PTR, class: Packet.CLASS.IN, ttl: 300, domain: FIXTURES.ptr },
    { name, type: Packet.TYPE.TXT, class: Packet.CLASS.IN, ttl: 300, data: ['v=spf1', ' include:mail.example.test ~all'] },
    { name, type: Packet.TYPE.SPF, class: Packet.CLASS.IN, ttl: 300, data: 'v=spf1 include:spf.example.test -all' },
    {
      name,
      type: Packet.TYPE.DNSKEY,
      class: Packet.CLASS.IN,
      ttl: 300,
      flags: 256,
      protocol: 3,
      algorithm: 13,
      key: 'PM8S6PI0Gf8d3HK9gHSVpW3X3zeieMEa+PLCijFuaFgiIANdUQen5xNn0/9+eo3E4VIJGU27lk6q4xXqMuQl7A==',
    },
  );

  response.authorities.push(
    { name, type: Packet.TYPE.NS, class: Packet.CLASS.IN, ttl: 300, ns: FIXTURES.ns },
    {
      name,
      type: Packet.TYPE.SOA,
      class: Packet.CLASS.IN,
      ttl: 300,
      primary: FIXTURES.ns,
      admin: 'admin.example.test',
      serial: 2026031101,
      refresh: 300,
      retry: 60,
      expiration: 600,
      minimum: 60,
    },
  );

  response.additionals.push(
    {
      name: FIXTURES.srv,
      type: Packet.TYPE.SRV,
      class: Packet.CLASS.IN,
      ttl: 300,
      priority: 10,
      weight: 5,
      port: 8443,
      target: FIXTURES.alias,
    },
    new Packet.Resource.EDNS([
      new Packet.Resource.EDNS.ECS('203.0.113.0/24'),
      new Packet.Resource.EDNS.ECS('198.51.100.7/32'),
    ]),
  );

  return response;
};

export const createRrsigResourceBuffer = (): Buffer => {
  const writer = new Packet.Writer();
  const signature = Buffer.from([1, 2, 3, 4, 5, 6]);
  const signer = Packet.Name.encode(FIXTURES.signer);
  const expiration = Math.floor(Date.parse('2026-01-02T03:04:05Z') / 1000);
  const inception = Math.floor(Date.parse('2025-12-01T00:00:00Z') / 1000);
  const rdLength = 18 + signer.length + signature.length;

  Packet.Name.encode(FIXTURES.domain, writer);
  writer.write(Packet.TYPE.RRSIG, 16);
  writer.write(Packet.CLASS.IN, 16);
  writer.write(300, 32);
  writer.write(rdLength, 16);
  writer.write(Packet.TYPE.A, 16);
  writer.write(13, 8);
  writer.write(2, 8);
  writer.write(300, 32);
  writer.write(expiration, 32);
  writer.write(inception, 32);
  writer.write(12345, 16);
  Packet.Name.encode(FIXTURES.signer, writer);
  for (const byte of signature) {
    writer.write(byte, 8);
  }

  return writer.toBuffer();
};

export const createUnknownResourceBuffer = (): Buffer => {
  const writer = new Packet.Writer();
  Packet.Name.encode(FIXTURES.domain, writer);
  writer.write(0xff10, 16);
  writer.write(Packet.CLASS.IN, 16);
  writer.write(120, 32);
  writer.write(3, 16);
  writer.write(0xaa, 8);
  writer.write(0xbb, 8);
  writer.write(0xcc, 8);
  return writer.toBuffer();
};

export const createPacketBufferRequest = (name = FIXTURES.domain, type = 'A'): Packet => {
  const packet = new Packet();
  packet.header.id = 4242;
  packet.header.rd = 1;
  packet.questions.push({
    name,
    type: Packet.TYPE[type as keyof typeof Packet.TYPE],
    class: Packet.CLASS.IN,
  });
  return packet;
};

export const startUdpServer = async (handler?: Parameters<typeof createUDPServer>[0]): Promise<{
  server: UDPServer;
  port: number;
}> => {
  const server = createUDPServer(handler);
  await server.listen(0, '127.0.0.1');
  const address = server.address();
  if (typeof address === 'string') {
    throw new Error('Expected UDP server address info');
  }
  return { server, port: address.port };
};

export const startTcpServer = async (handler?: Parameters<typeof createTCPServer>[0]): Promise<{
  server: TCPServer;
  port: number;
}> => {
  const server = createTCPServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Expected TCP server address info');
  }
  return { server, port: address.port };
};

export const startDohServer = async (options?: Parameters<typeof createDOHServer>[0]): Promise<{
  server: DOHServer;
  port: number;
}> => {
  const server = createDOHServer(options);
  server.listen(0, '127.0.0.1');
  const [address] = await once(server, 'listening');
  if (!address || typeof address === 'string') {
    throw new Error('Expected DoH server address info');
  }
  return { server, port: address.port };
};

export const startDnsServer = async (options: Parameters<typeof createServer>[0]): Promise<{
  server: DNSServer;
  addresses: Awaited<ReturnType<DNSServer['listen']>>;
}> => {
  const server = createServer(options);
  const addresses = await server.listen({
    udp: { port: 0, address: '127.0.0.1' },
    tcp: { port: 0, address: '127.0.0.1' },
    doh: { port: 0, address: '127.0.0.1' },
  });
  return { server, addresses };
};

export const closeServer = async (server: UDPServer | TCPServer | DOHServer | DNSServer): Promise<void> => {
  if (server instanceof DNS.DNSServer) {
    await server.close();
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once('error', onError);
    if ('server' in server) {
      server.close();
      server.once('close', () => {
        server.off('error', onError);
        resolve();
      });
      return;
    }
    server.close(() => {
      server.off('error', onError);
      resolve();
    });
  });
};

export const dohGet = async (port: number, packet: Packet, headers: Record<string, string> = {}) => {
  const url = `http://127.0.0.1:${port}/dns-query?dns=${packet.toBase64URL()}`;
  return new Promise<{ statusCode?: number; headers: http.IncomingHttpHeaders; body: Buffer }>((resolve, reject) => {
    const request = http.get(url, {
      headers: {
        accept: 'application/dns-message',
        ...headers,
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
      response.on('error', reject);
    });
    request.on('error', reject);
  });
};

export const dohPost = async (port: number, packet: Buffer | Packet, headers: Record<string, string> = {}) => {
  const payload = packet instanceof Packet ? packet.toBuffer() : packet;
  return new Promise<{ statusCode?: number; headers: http.IncomingHttpHeaders; body: Buffer }>((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path: '/dns-query',
      method: 'POST',
      headers: {
        accept: 'application/dns-message',
        'content-type': 'application/dns-message',
        'content-length': payload.length,
        ...headers,
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end(payload);
  });
};

export const sendMalformedTcpPayload = async (port: number, payload = 'INVALID'): Promise<void> => {
  await new Promise<void>((resolve, reject) => {
    const client = net.connect({ host: '127.0.0.1', port }, () => client.end(payload));
    client.on('close', () => resolve());
    client.on('error', reject);
  });
};
