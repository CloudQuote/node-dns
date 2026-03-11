import http from 'node:http';
import dgram from 'node:dgram';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';

import DNS, {
  DOHClient,
  TCPClient,
  UDPClient,
} from '../src/index.ts';
import Packet from '../src/packet.ts';
import {
  FIXTURES,
  closeServer,
  createPacketBufferRequest,
  createRrsigResourceBuffer,
  createRichResponse,
  dohGet,
  dohPost,
  sendMalformedTcpPayload,
  startDnsServer,
  startDohServer,
  startTcpServer,
  startUdpServer,
} from './helpers.ts';

const cleanup: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanup.length > 0) {
    const task = cleanup.pop();
    if (task) {
      await task();
    }
  }
  vi.restoreAllMocks();
});

const fetchText = async (options: http.RequestOptions): Promise<{ statusCode?: number; headers: http.IncomingHttpHeaders; body: string }> => {
  return new Promise((resolve, reject) => {
    const request = http.request(options, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString(),
      }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end();
  });
};

describe('transport integration', () => {
  it('serves UDP queries including EDNS client subnet metadata', async () => {
    const seenQuestions: Array<{ rd: number; clientIp?: string }> = [];
    const { server, port } = await startUdpServer(async (request, send) => {
      const ecs = request.additionals[0] as Packet.Resource & { rdata?: Array<{ ip: string }> };
      seenQuestions.push({
        rd: request.header.rd,
        clientIp: ecs?.rdata?.[0]?.ip,
      });
      await send(createRichResponse(request));
    });
    cleanup.push(() => closeServer(server));

    const response = await UDPClient({ dns: '127.0.0.1', port })(FIXTURES.domain, 'A', Packet.CLASS.IN, {
      clientIp: '198.51.100.7/32',
      recursive: true,
    });

    expect(seenQuestions).toEqual([{ rd: 1, clientIp: '198.51.100.7' }]);
    expect(response.answers.map(answer => answer.type)).toEqual([
      Packet.TYPE.A,
      Packet.TYPE.AAAA,
      Packet.TYPE.MX,
      Packet.TYPE.CNAME,
      Packet.TYPE.PTR,
      Packet.TYPE.TXT,
      Packet.TYPE.SPF,
      Packet.TYPE.DNSKEY,
    ]);
    expect(response.authorities.map(answer => answer.type)).toEqual([Packet.TYPE.NS, Packet.TYPE.SOA]);
    expect(response.additionals.map(answer => answer.type)).toEqual([Packet.TYPE.SRV, Packet.TYPE.EDNS]);
    expect(response.answers[0]).toMatchObject({ address: FIXTURES.ipv4 });
    expect(response.answers[1]).toMatchObject({ address: FIXTURES.ipv6 });
    expect(response.answers[2]).toMatchObject({ exchange: FIXTURES.mail, priority: 10 });
    expect(response.answers[3]).toMatchObject({ domain: FIXTURES.alias });
    expect(response.answers[4]).toMatchObject({ domain: FIXTURES.ptr });
    expect(response.answers[5]).toMatchObject({ data: 'v=spf1 include:mail.example.test ~all' });
    expect(response.answers[6]).toMatchObject({ data: 'v=spf1 include:spf.example.test -all' });
    expect(response.answers[7]).toMatchObject({ flags: 256, protocol: 3, algorithm: 13, zoneKey: true });
    expect(response.authorities[0]).toMatchObject({ ns: FIXTURES.ns });
    expect(response.authorities[1]).toMatchObject({ primary: FIXTURES.ns, admin: 'admin.example.test' });
    expect(response.additionals[0]).toMatchObject({ target: FIXTURES.alias, port: 8443 });
    expect((response.additionals[1] as Packet.Resource & { rdata: Array<{ ip: string }> }).rdata.map(item => item.ip))
      .toEqual(['203.0.113.0', '198.51.100.7']);
  });

  it('serves TCP queries end-to-end', async () => {
    const { server, port } = await startTcpServer((request, send) => {
      send(createRichResponse(request));
    });
    cleanup.push(() => closeServer(server));

    const response = await TCPClient({ dns: '127.0.0.1', port })(FIXTURES.domain, 'MX');
    expect(response.header.qr).toBe(1);
    expect(response.answers[2]).toMatchObject({ type: Packet.TYPE.MX, exchange: FIXTURES.mail });
  });

  it('serves DoH GET through the packaged client', async () => {
    const { server, port } = await startDohServer();
    cleanup.push(() => closeServer(server));
    server.on('request', (request, send) => {
      send(createRichResponse(request));
    });

    const response = await DOHClient({ dns: `http://127.0.0.1:${port}/dns-query` })(FIXTURES.domain, 'AAAA');
    expect(response.header.qr).toBe(1);
    expect(response.answers[1]).toMatchObject({ type: Packet.TYPE.AAAA, address: FIXTURES.ipv6 });
  });

  it('serves DoH POST requests and sets dns-message headers', async () => {
    const { server, port } = await startDohServer();
    cleanup.push(() => closeServer(server));
    server.on('request', (request, send) => {
      send(createRichResponse(request));
    });

    const payload = await dohPost(port, createPacketBufferRequest(FIXTURES.domain, 'TXT'));
    expect(payload.statusCode).toBe(200);
    expect(payload.headers['content-type']).toBe('application/dns-message');
    expect(Packet.parse(payload.body).answers[5]).toMatchObject({ type: Packet.TYPE.TXT });
  });

  it('serves UDP, TCP, and DoH concurrently through the combined DNS server', async () => {
    const { server, addresses } = await startDnsServer({
      udp: true,
      tcp: true,
      doh: true,
      handle(request, send) {
        send(createRichResponse(request as Packet));
      },
    });
    cleanup.push(() => closeServer(server));

    const udpPort = typeof addresses.udp === 'string' ? 0 : addresses.udp?.port ?? 0;
    const tcpPort = typeof addresses.tcp === 'string' ? 0 : addresses.tcp?.port ?? 0;
    const dohPort = typeof addresses.doh === 'string' ? 0 : addresses.doh?.port ?? 0;

    const [udpResponse, tcpResponse, dohResponse] = await Promise.all([
      UDPClient({ dns: '127.0.0.1', port: udpPort })(FIXTURES.domain, 'A'),
      TCPClient({ dns: '127.0.0.1', port: tcpPort })(FIXTURES.domain, 'A'),
      DOHClient({ dns: `http://127.0.0.1:${dohPort}/dns-query` })(FIXTURES.domain, 'A'),
    ]);

    expect(udpResponse.answers[0]).toMatchObject({ address: FIXTURES.ipv4 });
    expect(tcpResponse.answers[0]).toMatchObject({ address: FIXTURES.ipv4 });
    expect(dohResponse.answers[0]).toMatchObject({ address: FIXTURES.ipv4 });
  });

  it('propagates malformed request errors from every transport', async () => {
    const { server, addresses } = await startDnsServer({
      udp: true,
      tcp: true,
      doh: true,
      handle() {},
    });
    cleanup.push(() => closeServer(server));

    const errors: Error[] = [];
    server.on('requestError', error => errors.push(error));

    const udpPort = typeof addresses.udp === 'string' ? 0 : addresses.udp?.port ?? 0;
    const tcpPort = typeof addresses.tcp === 'string' ? 0 : addresses.tcp?.port ?? 0;
    const dohPort = typeof addresses.doh === 'string' ? 0 : addresses.doh?.port ?? 0;

    const socket = dgram.createSocket('udp4');
    await new Promise<void>((resolve, reject) => {
      socket.send(Buffer.from('INVALID'), udpPort, '127.0.0.1', (error) => {
        socket.close();
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
    await sendMalformedTcpPayload(tcpPort);
    await new Promise<void>((resolve) => {
      const request = http.request({
        host: '127.0.0.1',
        port: dohPort,
        path: '/dns-query',
        method: 'POST',
        headers: {
          accept: 'application/dns-message',
          'content-type': 'application/dns-message',
          'content-length': 7,
        },
      });
      request.on('error', () => resolve());
      request.on('close', () => resolve());
      request.end('INVALID');
    });

    expect(errors).toHaveLength(3);
  });
});

describe('DoH HTTP behavior', () => {
  it('applies cors headers for each supported mode', async () => {
    const defaultServer = await startDohServer();
    const noCorsServer = await startDohServer({ cors: false });
    const fixedServer = await startDohServer({ cors: 'https://allowed.test' });
    const functionServer = await startDohServer({
      cors(origin) {
        return origin === 'https://dynamic.test';
      },
    });
    cleanup.push(
      () => closeServer(defaultServer.server),
      () => closeServer(noCorsServer.server),
      () => closeServer(fixedServer.server),
      () => closeServer(functionServer.server),
    );

    const defaultResponse = await fetchText({
      host: '127.0.0.1',
      port: defaultServer.port,
      path: '/',
    });
    const noCorsResponse = await fetchText({
      host: '127.0.0.1',
      port: noCorsServer.port,
      path: '/',
    });
    const fixedResponse = await fetchText({
      host: '127.0.0.1',
      port: fixedServer.port,
      path: '/',
    });
    const dynamicResponse = await fetchText({
      host: '127.0.0.1',
      port: functionServer.port,
      path: '/',
      headers: { origin: 'https://dynamic.test' },
    });
    const blockedResponse = await fetchText({
      host: '127.0.0.1',
      port: functionServer.port,
      path: '/',
      headers: { origin: 'https://blocked.test' },
    });

    expect(defaultResponse.headers['access-control-allow-origin']).toBe('*');
    expect(noCorsResponse.headers['access-control-allow-origin']).toBeUndefined();
    expect(fixedResponse.headers['access-control-allow-origin']).toBe('https://allowed.test');
    expect(fixedResponse.headers.vary).toBe('Origin');
    expect(dynamicResponse.headers['access-control-allow-origin']).toBe('https://dynamic.test');
    expect(blockedResponse.headers['access-control-allow-origin']).toBe('false');
  });

  it('rejects invalid DoH HTTP requests with the expected status codes', async () => {
    const { server, port } = await startDohServer();
    cleanup.push(() => closeServer(server));

    const methodResult = await fetchText({
      host: '127.0.0.1',
      port,
      path: '/dns-query',
      method: 'PUT',
      headers: { accept: 'application/dns-message' },
    });

    const missingDnsResult = await fetchText({
      host: '127.0.0.1',
      port,
      path: '/dns-query',
      headers: { accept: 'application/dns-message' },
    });

    const badAcceptResult = await fetchText({
      host: '127.0.0.1',
      port,
      path: '/dns-query?dns=AA',
      headers: { accept: 'text/plain' },
    });

    const invalidPathResult = await fetchText({
      host: '127.0.0.1',
      port,
      path: '/wrong-path',
      headers: { accept: 'application/dns-message' },
    });

    expect(methodResult).toMatchObject({ statusCode: 405 });
    expect(missingDnsResult).toMatchObject({ statusCode: 400 });
    expect(badAcceptResult).toMatchObject({ statusCode: 400 });
    expect(invalidPathResult).toMatchObject({ statusCode: 404 });
  });
});

describe('DNS facade and external clients', () => {
  it('resolves through the DNS facade for UDP, TCP, and DoH', async () => {
    const udp = await startUdpServer((request, send) => {
      if (request.questions[0]?.type === Packet.TYPE.RRSIG) {
        const header = new Packet.Header({
          id: request.header.id,
          qr: 1,
          rd: request.header.rd,
          ra: 1,
          qdcount: 1,
          ancount: 1,
        });
        const payload = Buffer.concat([
          header.toBuffer(),
          Packet.Question.encode(request.questions[0]),
          createRrsigResourceBuffer(),
        ]);
        send(payload);
        return;
      }
      send(createRichResponse(request));
    });
    const tcp = await startTcpServer((request, send) => send(createRichResponse(request)));
    const doh = await startDohServer();
    doh.server.on('request', (request, send) => send(createRichResponse(request)));
    cleanup.push(
      () => closeServer(udp.server),
      () => closeServer(tcp.server),
      () => closeServer(doh.server),
    );

    const udpResolver = new DNS({ port: udp.port, nameServers: ['127.0.0.1'], resolverProtocol: 'UDP' });
    const tcpResolver = new DNS({ port: tcp.port, nameServers: ['127.0.0.1'], resolverProtocol: 'TCP' });
    const dohResolver = new DNS({
      nameServers: [`http://127.0.0.1:${doh.port}/dns-query`],
      resolverProtocol: 'DOH',
    });

    await expect(udpResolver.resolveA(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.A, address: FIXTURES.ipv4 })]),
    });
    await expect(udpResolver.resolveAAAA(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.AAAA, address: FIXTURES.ipv6 })]),
    });
    await expect(udpResolver.resolveMX(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.MX, exchange: FIXTURES.mail })]),
    });
    await expect(udpResolver.resolveCNAME(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.CNAME, domain: FIXTURES.alias })]),
    });
    await expect(udpResolver.resolvePTR(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.PTR, domain: FIXTURES.ptr })]),
    });
    await expect(udpResolver.resolveDNSKEY(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.DNSKEY, protocol: 3 })]),
    });
    await expect(udpResolver.resolveRRSIG(FIXTURES.domain)).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.RRSIG })]),
    });
    await expect(tcpResolver.resolve(FIXTURES.domain, 'TXT')).resolves.toMatchObject({
      answers: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.TXT })]),
    });
    await expect(dohResolver.resolve(FIXTURES.domain, 'NS')).resolves.toMatchObject({
      authorities: expect.arrayContaining([expect.objectContaining({ type: Packet.TYPE.NS, ns: FIXTURES.ns })]),
    });
  });

  it('parses JSON responses from GoogleClient without hitting the network', async () => {
    const body = JSON.stringify({
      Status: 0,
      Question: [{ name: FIXTURES.domain, type: 1 }],
      Answer: [{ name: FIXTURES.domain, type: 1, TTL: 60, data: FIXTURES.ipv4 }],
    });

    const getMock = vi.fn((url: string, callback: (message: http.IncomingMessage) => void) => {
      const stream = new PassThrough() as unknown as http.IncomingMessage;
      process.nextTick(() => {
        callback(stream);
        (stream as unknown as PassThrough).end(body);
      });
      return { on: () => undefined };
    });
    vi.resetModules();
    vi.doMock('node:https', () => ({ get: getMock }));

    const { default: GoogleClient } = await import('../src/client/google.ts');
    const result = await GoogleClient()(FIXTURES.domain, 'A');
    expect(getMock).toHaveBeenCalledWith(
      `https://dns.google.com/resolve?name=${FIXTURES.domain}&type=A`,
      expect.any(Function),
    );
    expect(result).toEqual(JSON.parse(body));
  });
});
