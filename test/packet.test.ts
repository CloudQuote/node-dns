import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';

import Packet, {EdnsClientSubnetOption, EDNSRecord, Resource } from '../src/packet.ts';
import {
  FIXTURES,
  createPacketBufferRequest,
  createRichResponse,
  createRrsigResourceBuffer,
  createUnknownResourceBuffer,
} from './helpers.ts';

describe('packet and codec coverage', () => {
  it('round-trips the core packet codec with every implemented two-way RR handler', () => {
    const request = createPacketBufferRequest(FIXTURES.domain, 'A');
    const response = createRichResponse(request);
    const parsed = Packet.parse(response.toBuffer());

    expect(parsed.header).toMatchObject({
      qr: 1,
      qdcount: 1,
      ancount: 8,
      nscount: 2,
      arcount: 2,
    });
    expect(parsed.questions[0]).toEqual({
      name: FIXTURES.domain,
      type: Packet.TYPE.A,
      class: Packet.CLASS.IN,
    });
    expect(parsed.answers[0]).toMatchObject({ type: Packet.TYPE.A, address: FIXTURES.ipv4 });
    expect(parsed.answers[1]).toMatchObject({ type: Packet.TYPE.AAAA, address: FIXTURES.ipv6 });
    expect(parsed.answers[2]).toMatchObject({ type: Packet.TYPE.MX, exchange: FIXTURES.mail, priority: 10 });
    expect(parsed.answers[3]).toMatchObject({ type: Packet.TYPE.CNAME, domain: FIXTURES.alias });
    expect(parsed.answers[4]).toMatchObject({ type: Packet.TYPE.PTR, domain: FIXTURES.ptr });
    expect(parsed.answers[5]).toMatchObject({ type: Packet.TYPE.TXT, data: 'v=spf1 include:mail.example.test ~all' });
    expect(parsed.answers[6]).toMatchObject({ type: Packet.TYPE.SPF, data: 'v=spf1 include:spf.example.test -all' });
    expect(parsed.answers[7]).toMatchObject({ type: Packet.TYPE.DNSKEY, flags: 256, keyTag: 1721, zoneKey: true });
    expect(parsed.authorities[0]).toMatchObject({ type: Packet.TYPE.NS, ns: FIXTURES.ns });
    expect(parsed.authorities[1]).toMatchObject({ type: Packet.TYPE.SOA, primary: FIXTURES.ns, admin: 'admin.example.test' });
    expect(parsed.additionals[0]).toMatchObject({ type: Packet.TYPE.SRV, target: FIXTURES.alias, port: 8443 });
    expect((parsed.additionals[1] as EDNSRecord).rdata.map((item: EdnsClientSubnetOption) => item.ip))
      .toEqual(['203.0.113.0', '198.51.100.7']);
  });

  it('encodes and decodes DNS names, IPv6 helpers, and packet constructors', () => {
    const encodedName = Packet.Name.encode('www.example.test');
    expect(Packet.Name.decode(encodedName)).toBe('www.example.test');
    expect(Packet.toIPv6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])).toBe('2001:db8::1');
    expect(Packet.fromIPv6('2001:db8::1')).toEqual(['2001', '0db8', '0000', '0000', '0000', '0000', '0000', '0001']);

    const packet = new Packet('www.example.test');
    expect(packet.questions).toEqual([{ name: 'www.example.test', type: Packet.TYPE.ANY, class: Packet.CLASS.ANY }]);

    const response = Packet.createResponseFromRequest(createPacketBufferRequest('service.example.test', 'SRV'));
    expect(response.header.qr).toBe(1);
    expect(response.additionals).toEqual([]);

    const resource = Packet.createResourceFromQuestion(
      { name: 'service.example.test', type: Packet.TYPE.SRV, class: Packet.CLASS.IN },
      { ttl: 42, target: FIXTURES.alias },
    );
    expect(resource).toMatchObject({ name: 'service.example.test', type: Packet.TYPE.SRV, ttl: 42, target: FIXTURES.alias });
  });

  it('encodes CAA resources and falls back for unknown RR decoders', () => {
    const encodedCaa = Packet.Resource.encode({
      name: FIXTURES.domain,
      type: Packet.TYPE.CAA,
      class: Packet.CLASS.IN,
      ttl: 300,
      flags: 0,
      tag: 'issue',
      value: 'letsencrypt.org',
    });

    const parsedUnknown = Packet.Resource.decode(createUnknownResourceBuffer());

    expect(encodedCaa.subarray(-24)).toEqual(Buffer.from([
      0x00, 0x16,
      0x00,
      0x05,
      ...Buffer.from('issueletsencrypt.org', 'utf8'),
    ]));
    expect(parsedUnknown).toMatchObject({
      type: 0xff10,
      class: Packet.CLASS.IN,
      ttl: 120,
      data: Buffer.from([0xaa, 0xbb, 0xcc]),
    });
  });

  it('decodes RRSIG resources from raw wire data', () => {
    const record = Packet.Resource.decode(createRrsigResourceBuffer()) as Resource & {
      sigType: number;
      algorithm: number;
      labels: number;
      originalTtl: number;
      expiration: string;
      inception: string;
      keyTag: number;
      signer: string;
      signature: string;
    };

    expect(record).toMatchObject({
      type: Packet.TYPE.RRSIG,
      sigType: Packet.TYPE.A,
      algorithm: 13,
      labels: 2,
      originalTtl: 300,
      expiration: '20260102030405',
      inception: '20251201000000',
      keyTag: 12345,
      signer: FIXTURES.signer,
      signature: Buffer.from([1, 2, 3, 4, 5, 6]).toString('base64'),
    });
  });

  it('reads length-prefixed TCP streams even when payload arrives in chunks', async () => {
    const packet = createRichResponse(createPacketBufferRequest(FIXTURES.domain)).toBuffer();
    const length = Buffer.alloc(2);
    length.writeUInt16BE(packet.length);

    const stream = new PassThrough();
    const read = Packet.readStream(stream);
    stream.write(length.subarray(0, 1));
    stream.write(Buffer.concat([length.subarray(1), packet.subarray(0, 8)]));
    stream.write(packet.subarray(8));
    stream.end();

    await expect(read).resolves.toEqual(packet);
  });

  it('preserves EDNS ECS records across encode/decode with multiple options', () => {
    const query = new Packet.Resource.EDNS([
      new Packet.Resource.EDNS.ECS('10.0.0.0/8'),
      new Packet.Resource.EDNS.ECS('10.9.0.0/16'),
      new Packet.Resource.EDNS.ECS('10.9.8.0/24'),
      new Packet.Resource.EDNS.ECS('10.9.8.7/32'),
    ]);

    const decoded = Packet.Resource.decode(Packet.Resource.encode(query)) as Resource & {
      rdata: Array<{ ip: string; sourcePrefixLength: number }>;
    };
    delete decoded.name;

    expect(decoded).toEqual(query);
  });

  it('produces bounded random ids', () => {
    const values = new Set(Array.from({ length: 32 }, () => Packet.uuid()));
    expect(Math.min(...values)).toBeGreaterThanOrEqual(0);
    expect(Math.max(...values)).toBeLessThan(100000);
  });
});
