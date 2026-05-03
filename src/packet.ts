import { debuglog } from 'node:util';

import BufferReader from './lib/reader.ts';
import BufferWriter from './lib/writer.ts';

const debug = debuglog('dns2');

export const TYPE: Record<string, number> = {
  A: 0x01,
  NS: 0x02,
  MD: 0x03,
  MF: 0x04,
  CNAME: 0x05,
  SOA: 0x06,
  MB: 0x07,
  MG: 0x08,
  MR: 0x09,
  NULL: 0x0A,
  WKS: 0x0B,
  PTR: 0x0C,
  HINFO: 0x0D,
  MINFO: 0x0E,
  MX: 0x0F,
  TXT: 0x10,
  AAAA: 0x1C,
  SRV: 0x21,
  EDNS: 0x29,
  RRSIG: 0x2E,
  DNSKEY: 0x30,
  SPF: 0x63,
  AXFR: 0xFC,
  MAILB: 0xFD,
  MAILA: 0xFE,
  ANY: 0xFF,
  CAA: 0x101,
};

export const CLASS: Record<string, number> = {
  IN: 0x01,
  CS: 0x02,
  CH: 0x03,
  HS: 0x04,
  ANY: 0xFF,
};

export const EDNS_OPTION_CODE: Record<string, number> = {
  ECS: 0x08,
};

type PacketTypeName = string;

export interface HeaderFields {
  id: number;
  qr: number;
  opcode: number;
  aa: number;
  tc: number;
  rd: number;
  ra: number;
  z: number;
  rcode: number;
  qdcount: number;
  ancount: number;
  nscount: number;
  arcount: number;
}

export interface QuestionFields {
  name: string;
  type: number;
  class: number;
}

export interface ResourceFields {
  name?: string;
  ttl: number;
  type: number;
  class: number;
  target?: string;
}

export type ARecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.A; address: string };
export type AAAARecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.AAAA; address: string };
export type CNAMERecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.CNAME; domain: string };
export type PTRRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.PTR; name: string };
export type MXRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.MX; exchange: string; priority: number };
export type TXTRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.TXT; data: Buffer|string|Array<string|Buffer> };
export type NSRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.NS; ns: string };
export type SOARecordType = Omit<ResourceFields,"type"> & {
  type: typeof TYPE.SOA; name: string; mname: string; rname: string;
  serial: number; refresh: number; retry: number; expire: number; minimum: number,
  primary: string; admin: string; expiration: number;
};
export type SRVRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.SRV; target: string; port: number; priority: number; weight: number };
export type OPTRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.OPT; edns: EDNSRecord };
export type EDNSRecordType = Omit<ResourceFields,"type"> & {
  type: typeof TYPE.EDNS;
  rdata: Array<EdnsOption|EdnsClientSubnetOption>
};
export type ECSRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.ECS; rdata: ECSOption };
export type SPFRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.SPF; text: string };
export type CAARecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.CAA; flags: number; tag: string; value: string };
export type DNSKeyRecordType = Omit<ResourceFields,"type"> & {
  type: typeof TYPE.DNSKEY; flags: number; protocol: number; algorithm: number;
  key: Buffer|string;
  zoneKey?: boolean, zoneSep?: boolean
};
export type RRSigRecordType = Omit<ResourceFields,"type"> & { type: typeof TYPE.RRSIG; typeCovered: number; algorithm: number; labels: number; originalTTL: number; expiration: number; inception: number; keyTag: number; signer: string; signature: Buffer };

type ResourceData =
  ARecordType |
  AAAARecordType |
  CNAMERecordType |
  PTRRecordType |
  MXRecordType |
  TXTRecordType |
  NSRecordType |
  SOARecordType |
  SRVRecordType |
  OPTRecordType |
  EDNSRecordType |
  ECSRecordType |
  SPFRecordType |
  CAARecordType |
  DNSKeyRecordType |
  RRSigRecordType;

export type ECSOptionRecordType = Omit<ECSOption, "ednsCode">;

export interface EdnsOption {
  ednsCode: number;
}

export interface EdnsClientSubnetOption extends EdnsOption {
  family: number;
  sourcePrefixLength: number;
  scopePrefixLength: number;
  ip: string;
}

export type PacketInput =
  | Packet
  | Header
  | Question
  | Resource
  | string
  | Partial<HeaderFields>
  | Partial<QuestionFields>[]
  | undefined;

type ReaderInput = BufferReader | Buffer;
type ResourceHandler<SpecificResourceType extends ResourceData> = {
  decode?: (this: Resource, reader: BufferReader, length: number) => Resource;
  encode?: (record: SpecificResourceType, writer?: BufferWriter) => Buffer;
};

const typeCodeToName = new Map<number, PacketTypeName>(
  Object.entries(TYPE).map(([name, value]) => [value, name as PacketTypeName]),
);

export const toIPv6 = (buffer: number[]): string => buffer
  .map(part => (part > 0 ? part.toString(16) : '0'))
  .join(':')
  .replace(/\b(?:0+:){1,}/, ':');

export const fromIPv6 = (address: string): string[] => {
  const digits = address.split(':');
  if (digits[0] === '') {
    digits.shift();
  }
  if (digits[digits.length - 1] === '') {
    digits.pop();
  }

  const missingFields = 8 - digits.length + 1;
  return digits.flatMap((digit) => {
    if (digit === '') {
      return Array(missingFields).fill('0000');
    }
    return digit.padStart(4, '0');
  });
};

const asReader = (reader: ReaderInput): BufferReader => (
  reader instanceof Buffer ? new BufferReader(reader) : (reader as BufferReader)
);

export class Header implements HeaderFields {
  id = 0;
  qr = 0;
  opcode = 0;
  aa = 0;
  tc = 0;
  rd = 0;
  ra = 0;
  z = 0;
  rcode = 0;
  qdcount = 0;
  ancount = 0;
  nscount = 0;
  arcount = 0;

  constructor(header: Partial<HeaderFields> = {}) {
    Object.assign(this, header);
  }

  static parse(reader: ReaderInput): Header {
    const source = asReader(reader);
    const header = new Header();
    header.id = source.read(16);
    header.qr = source.read(1);
    header.opcode = source.read(4);
    header.aa = source.read(1);
    header.tc = source.read(1);
    header.rd = source.read(1);
    header.ra = source.read(1);
    header.z = source.read(3);
    header.rcode = source.read(4);
    header.qdcount = source.read(16);
    header.ancount = source.read(16);
    header.nscount = source.read(16);
    header.arcount = source.read(16);
    return header;
  }

  toBuffer(writer = new BufferWriter()): Buffer {
    writer.write(this.id, 16);
    writer.write(this.qr, 1);
    writer.write(this.opcode, 4);
    writer.write(this.aa, 1);
    writer.write(this.tc, 1);
    writer.write(this.rd, 1);
    writer.write(this.ra, 1);
    writer.write(this.z, 3);
    writer.write(this.rcode, 4);
    writer.write(this.qdcount, 16);
    writer.write(this.ancount, 16);
    writer.write(this.nscount, 16);
    writer.write(this.arcount, 16);
    return writer.toBuffer();
  }
}

export class Question implements QuestionFields {
  name = '';
  type = TYPE.ANY;
  class = CLASS.ANY;

  constructor(name?: string | Partial<QuestionFields>, type = TYPE.ANY, cls = CLASS.ANY) {
    if (typeof name === 'object' && name !== null) {
      this.name = name.name ?? this.name;
      this.type = name.type ?? this.type;
      this.class = name.class ?? this.class;
      return;
    }

    this.name = typeof name === 'string' ? name : this.name;
    this.type = type;
    this.class = cls;
  }

  static parse(reader: ReaderInput): Question {
    return Question.decode(reader);
  }

  static decode(reader: ReaderInput): Question {
    const source = asReader(reader);
    const question = new Question();
    question.name = Packet.Name.decode(source);
    question.type = source.read(16);
    question.class = source.read(16);
    return question;
  }

  static encode(question: QuestionFields, writer = new BufferWriter()): Buffer {
    Packet.Name.encode(question.name, writer);
    writer.write(question.type, 16);
    writer.write(question.class, 16);
    return writer.toBuffer();
  }

  toBuffer(writer = new BufferWriter()): Buffer {
    return Question.encode(this, writer);
  }
}

export class Resource implements ResourceFields {
  name = '';
  ttl = 300;
  type = TYPE.ANY;
  class = CLASS.ANY;
  [key: string]: unknown;

  constructor(name?: string | Partial<ResourceFields>, type = TYPE.ANY, cls = CLASS.ANY, ttl = 300) {
    if (typeof name === 'object' && name !== null) {
      Object.assign(this, {
        name: '',
        ttl: 300,
        type: TYPE.ANY,
        class: CLASS.ANY,
      }, name);
      return;
    }

    Object.assign(this, {
      name: name ?? '',
      type,
      class: cls,
      ttl,
    });
  }

  static parse(reader: ReaderInput): Resource {
    return Resource.decode(reader);
  }

  static encode(resource: ResourceData, writer = new BufferWriter()): Buffer {
    Packet.Name.encode(resource.name, writer);
    writer.write(resource.type, 16);
    writer.write(resource.class, 16);
    writer.write(resource.ttl, 32);

    const encoderName = typeCodeToName.get(resource.type);
    const handler = encoderName ? Resource[encoderName] : undefined;
    if (handler?.encode) {
      return handler.encode(resource, writer);
    }

    debug('node-dns > unknown encoder %s(%j)', encoderName, resource.type);
    return writer.toBuffer();
  }

  static decode(reader: ReaderInput): Resource {
    const source = asReader(reader);
    let resource = new Resource();
    resource.name = Packet.Name.decode(source);
    resource.type = source.read(16);
    resource.class = source.read(16);
    resource.ttl = source.read(32);
    let length = source.read(16);

    const parserName = typeCodeToName.get(resource.type);
    const handler = parserName ? Resource[parserName] : undefined;
    if (handler?.decode) {
      resource = handler.decode.call(resource, source, length);
    } else {
      debug('node-dns > unknown parser type: %s(%j)', parserName, resource.type);
      const bytes: number[] = [];
      while (length > 0) {
        bytes.push(source.read(8));
        length -= 1;
      }
      resource.data = Buffer.from(bytes);
    }
    return resource;
  }

  toBuffer(writer = new BufferWriter()): Buffer {
    return Resource.encode(this, writer);
  }
}

export class ARecord {
  type: number;
  class: number;
  address: string;

  constructor(address: string) {
    this.type = TYPE.A;
    this.class = CLASS.IN;
    this.address = address;
  }

  static encode(record: ARecordType, writer = new BufferWriter()): Buffer {
    const address = String(record.address ?? '');
    const parts = address.split('.');
    writer.write(parts.length, 16);
    parts.forEach((part) => {
      writer.write(Number.parseInt(part, 10), 8);
    });
    return writer.toBuffer();
  }

  static decode(this: Resource, reader: BufferReader, length: number): Resource {
    const parts: number[] = [];
    while (length > 0) {
      parts.push(reader.read(8));
      length -= 1;
    }
    this.address = parts.join('.');
    return this;
  }
}

export class MXRecord {
  type: number;
  class: number;
  exchange: string;
  priority: number;

  constructor(exchange: string, priority: number) {
    this.type = TYPE.MX;
    this.class = CLASS.IN;
    this.exchange = exchange;
    this.priority = priority;
  }

  static encode(record: MXRecordType, writer = new BufferWriter()): Buffer {
    const exchange = String(record.exchange ?? '');
    const priority = Number(record.priority ?? 0);
    const length = Packet.Name.encode(exchange).length;
    writer.write(length + 2, 16);
    writer.write(priority, 16);
    Packet.Name.encode(exchange, writer);
    return writer.toBuffer();
  }

  static decode(this: Resource, reader: BufferReader): Resource {
    this.priority = reader.read(16);
    this.exchange = Packet.Name.decode(reader);
    return this;
  }
}

export class EDNSRecord {
  type: number;
  class: number;
  ttl: number;
  rdata: Array<EdnsOption|EdnsClientSubnetOption>;

  constructor(rdata: Array<EdnsOption|EdnsClientSubnetOption> = []) {
    this.type = TYPE.EDNS;
    this.class = 512;
    this.ttl = 0;
    this.rdata = rdata;
  }

  static decode(reader: BufferReader, length: number): EDNSRecordType {
    const record = Object.assign(Object.create(EDNSRecord.prototype), {
      type: TYPE.EDNS,
      class: 512,
      ttl: 0,
      rdata: [] as EdnsOption[],
    }) as Resource & EDNSRecord;

    while (length > 0) {
      const optionCode = reader.read(16);
      const optionLength = reader.read(16);
      const decoderName = Object.entries(EDNS_OPTION_CODE)
        .find(([, value]) => value === optionCode)?.[0];
      const decoder = decoderName
        ? EDNSRecord[decoderName]
        : undefined;

      if (decoder?.decode) {
        record.rdata.push(decoder.decode.call(new Resource(), reader, optionLength) as unknown as EdnsOption);
      } else {
        reader.read(optionLength);
        debug('node-dns > unknown EDNS rdata decoder %s(%j)', decoderName, optionCode);
      }

      length = length - 4 - optionLength;
    }

    return record;
  }

  static encode(record: EDNSRecordType, writer = new BufferWriter()): Buffer {
    const rdataWriter = new BufferWriter();
    const rdata = Array.isArray(record.rdata) ? record.rdata as EdnsOption[] : [];

    for (const option of rdata) {
      const encoderName = Object.entries(EDNS_OPTION_CODE)
        .find(([, value]) => value === option.ednsCode)?.[0];
      const encoder = encoderName
        ? EDNSRecord[encoderName]
        : undefined;

      if (encoder?.encode) {
        const optionWriter = new BufferWriter();
        encoder.encode(option as unknown as ResourceData, optionWriter);
        rdataWriter.write(option.ednsCode, 16);
        rdataWriter.write(optionWriter.buffer.length / 8, 16);
        rdataWriter.writeBuffer(optionWriter);
      } else {
        debug('node-dns > unknown EDNS rdata encoder %s(%j)', encoderName, option.ednsCode);
      }
    }

    writer.write(rdataWriter.buffer.length / 8, 16);
    writer.writeBuffer(rdataWriter);
    return writer.toBuffer();
  }
}

export class ECSOption {
  ednsCode = EDNS_OPTION_CODE.ECS;
  family = 1;
  sourcePrefixLength: number;
  scopePrefixLength = 0;
  ip: string;

  constructor(clientIp: string) {
    const [ip, prefixLength] = clientIp.split('/');
    this.ip = ip;
    this.sourcePrefixLength = Number.parseInt(prefixLength ?? '', 10) || 32;
  }

  static decode(reader: BufferReader, length: number): Resource {
    const record = Object.assign(Object.create(ECSOption.prototype), {
      ednsCode: EDNS_OPTION_CODE.ECS,
      family: reader.read(16),
      sourcePrefixLength: reader.read(8),
      scopePrefixLength: reader.read(8),
    }) as Resource & ECSOption;
    length -= 4;

    if (record.family === 1) {
      const ipv4Octets: number[] = [];
      while (length > 0) {
        ipv4Octets.push(reader.read(8));
        length -= 1;
      }
      while (ipv4Octets.length < 4) {
        ipv4Octets.push(0);
      }
      record.ip = ipv4Octets.join('.');
    }

    if (record.family === 2) {
      const ipv6Segments: string[] = [];
      while (length > 0) {
        ipv6Segments.push(reader.read(16).toString(16));
        length -= 2;
      }
      while (ipv6Segments.length < 8) {
        ipv6Segments.push('0');
      }
      record.ip = ipv6Segments.join(':');
    }

    return record;
  }

  static encode(record: ECSOptionRecordType, writer = new BufferWriter()): Buffer {
    const ip = String(record.ip ?? '').split('.').map(part => Number.parseInt(part, 10));
    writer.write(Number(record.family ?? 1), 16);
    writer.write(Number(record.sourcePrefixLength ?? 32), 8);
    writer.write(Number(record.scopePrefixLength ?? 0), 8);
    writer.write(ip[0] ?? 0, 8);
    writer.write(ip[1] ?? 0, 8);
    writer.write(ip[2] ?? 0, 8);
    writer.write(ip[3] ?? 0, 8);
    return writer.toBuffer();
  }
}

const AAAAHandler: ResourceHandler<AAAARecordType> = {
  decode(reader, length) {
    const parts: number[] = [];
    while (length > 0) {
      length -= 2;
      parts.push(reader.read(16));
    }
    this.address = toIPv6(parts);
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    const parts = fromIPv6(String(record.address ?? ''));
    writer.write(parts.length * 2, 16);
    parts.forEach((part) => {
      writer.write(Number.parseInt(part, 16), 16);
    });
    return writer.toBuffer();
  },
};

const NSHandler: ResourceHandler<NSRecordType> = {
  decode(reader) {
    this.ns = Packet.Name.decode(reader);
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    const ns = String(record.ns ?? '');
    writer.write(Packet.Name.encode(ns).length, 16);
    Packet.Name.encode(ns, writer);
    return writer.toBuffer();
  },
};

const CNAMEHandler: ResourceHandler<CNAMERecordType> = {
  decode(reader) {
    this.domain = Packet.Name.decode(reader);
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    const domain = String(record.domain ?? '');
    writer.write(Packet.Name.encode(domain).length, 16);
    Packet.Name.encode(domain, writer);
    return writer.toBuffer();
  },
};

const TXTHandler: ResourceHandler<TXTRecordType> = {
  decode(reader, length) {
    const parts: number[] = [];
    let bytesRead = 0;

    while (bytesRead < length) {
      let chunkLength = reader.read(8);
      bytesRead += 1;

      while (chunkLength > 0) {
        parts.push(reader.read(8));
        bytesRead += 1;
        chunkLength -= 1;
      }
    }

    this.data = Buffer.from(parts).toString('utf8');
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    const characterStrings = Array.isArray(record.data) ? record.data : [record.data];
    const buffers = characterStrings
      .map((value) => {
        if (Buffer.isBuffer(value)) {
          return value;
        }
        if (typeof value === 'string') {
          return Buffer.from(value, 'utf8');
        }
        return null;
      })
      .filter((value): value is Buffer => value !== null);

    const totalLength = buffers.reduce((sum, buffer) => sum + buffer.length, 0);
    writer.write(totalLength + buffers.length, 16);

    buffers.forEach((buffer) => {
      writer.write(buffer.length, 8);
      buffer.forEach((value) => {
        writer.write(value, 8);
      });
    });

    return writer.toBuffer();
  },
};

const SOAHandler: ResourceHandler<SOARecordType> = {
  decode(reader) {
    this.primary = Packet.Name.decode(reader);
    this.admin = Packet.Name.decode(reader);
    this.serial = reader.read(32);
    this.refresh = reader.read(32);
    this.retry = reader.read(32);
    this.expiration = reader.read(32);
    this.minimum = reader.read(32);
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    let length = 0;
    length += Packet.Name.encode(String(record.primary ?? '')).length;
    length += Packet.Name.encode(String(record.admin ?? '')).length;
    length += (32 * 5) / 8;
    writer.write(length, 16);
    Packet.Name.encode(String(record.primary ?? ''), writer);
    Packet.Name.encode(String(record.admin ?? ''), writer);
    writer.write(Number(record.serial ?? 0), 32);
    writer.write(Number(record.refresh ?? 0), 32);
    writer.write(Number(record.retry ?? 0), 32);
    writer.write(Number(record.expiration ?? 0), 32);
    writer.write(Number(record.minimum ?? 0), 32);
    return writer.toBuffer();
  },
};

const SRVHandler: ResourceHandler<SRVRecordType> = {
  decode(reader) {
    this.priority = reader.read(16);
    this.weight = reader.read(16);
    this.port = reader.read(16);
    this.target = Packet.Name.decode(reader);
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    const target = String(record.target ?? '');
    const { length } = Packet.Name.encode(target);
    writer.write(length + 6, 16);
    writer.write(Number(record.priority ?? 0), 16);
    writer.write(Number(record.weight ?? 0), 16);
    writer.write(Number(record.port ?? 0), 16);
    Packet.Name.encode(target, writer);
    return writer.toBuffer();
  },
};

const CAAHandler: ResourceHandler<CAARecordType> = {
  encode(record, writer = new BufferWriter()) {
    const tag = String(record.tag ?? '');
    const value = String(record.value ?? '');
    const buffer = Buffer.from(tag + value, 'utf8');
    writer.write(2 + buffer.length, 16);
    writer.write(Number(record.flags ?? 0), 8);
    writer.write(tag.length, 8);
    buffer.forEach((byte) => writer.write(byte, 8));
    return writer.toBuffer();
  },
};

const DNSKEYHandler: ResourceHandler<DNSKeyRecordType> = {
  decode(reader, length) {
    const rdata: number[] = [];
    while (rdata.length < length) {
      rdata.push(reader.read(8));
    }

    this.flags = (rdata[0] << 8) | rdata[1];
    this.protocol = rdata[2];
    this.algorithm = rdata[3];

    let ac = 0;
    for (let i = 0; i < length; i += 1) {
      ac += (i & 1) ? rdata[i] : rdata[i] << 8;
    }
    ac += (ac >> 16) & 0xFFFF;
    this.keyTag = ac & 0xFFFF;

    let binFlags = Number(this.flags).toString(2);
    while (binFlags.length < 16) {
      binFlags = `0${binFlags}`;
    }
    this.zoneKey = binFlags[7] === '1';
    this.zoneSep = binFlags[15] === '1';
    this.key = Buffer.from(rdata.slice(4)).toString('base64');
    return this;
  },
  encode(record, writer = new BufferWriter()) {
    const buffer = Buffer.from(String(record.key ?? ''), 'base64');
    writer.write(4 + buffer.length, 16);
    writer.write(Number(record.flags ?? 0), 16);
    writer.write(Number(record.protocol ?? 0), 8);
    writer.write(Number(record.algorithm ?? 0), 8);
    buffer.forEach((byte) => writer.write(byte, 8));
    return writer.toBuffer();
  },
};

const RRSIGHandler: ResourceHandler<RRSigRecordType> = {
  decode(reader, length) {
    const dateForSig = (date: number) => {
      const value = new Date(date * 1000);
      const parts = {
        month: value.getUTCMonth() + 1,
        date: value.getUTCDate(),
        hour: value.getUTCHours(),
        minutes: value.getUTCMinutes(),
        seconds: value.getUTCSeconds(),
      };

      const normalized = Object.fromEntries(
        Object.entries(parts).map(([key, part]) => [key, part < 10 ? `0${part}` : `${part}`]),
      ) as Record<string, string>;

      return `${value.getUTCFullYear()}${normalized.month}${normalized.date}${normalized.hour}${normalized.minutes}${normalized.seconds}`;
    };

    const maxOffset = reader.offset + (length * 8);
    this.sigType = reader.read(16);
    this.algorithm = reader.read(8);
    this.labels = reader.read(8);
    this.originalTtl = reader.read(32);
    this.expiration = dateForSig(reader.read(32));
    this.inception = dateForSig(reader.read(32));
    this.keyTag = reader.read(16);
    this.signer = Packet.Name.decode(reader);

    const maxLength = (maxOffset - reader.offset) / 8;
    const signature: number[] = [];
    while (signature.length < maxLength) {
      signature.push(reader.read(8));
    }
    this.signature = Buffer.from(signature).toString('base64');
    return this;
  },
};

Object.assign(Resource, {
  A: ARecord,
  MX: MXRecord,
  AAAA: AAAAHandler,
  NS: NSHandler,
  PTR: CNAMEHandler,
  CNAME: CNAMEHandler,
  SPF: TXTHandler,
  TXT: TXTHandler,
  SOA: SOAHandler,
  SRV: SRVHandler,
  EDNS: EDNSRecord,
  CAA: CAAHandler,
  DNSKEY: DNSKEYHandler,
  RRSIG: RRSIGHandler,
});

Object.assign(EDNSRecord, {
  ECS: ECSOption,
});

export default class Packet {
  header: Header;
  questions: Array<Question | QuestionFields>;
  answers: Array<ResourceData>;
  authorities: Array<ResourceData>;
  additionals: Array<ResourceData|EDNSRecord>;


  static toIPv6 = toIPv6;
  static fromIPv6 = fromIPv6;
  static TYPE = TYPE;
  static CLASS = CLASS;
  static EDNS_OPTION_CODE = EDNS_OPTION_CODE;
  static Reader = BufferReader;
  static Writer = BufferWriter;
  static Header = Header;
  static Question = Question;
  static Resource = Resource as typeof Resource & {
    A: typeof ARecord;
    MX: typeof MXRecord;
    AAAA: ResourceHandler<AAAARecordType>;
    NS: ResourceHandler<NSRecordType>;
    PTR: ResourceHandler<PTRRecordType>;
    CNAME: ResourceHandler<CNAMERecordType>;
    SPF: ResourceHandler<SPFRecordType>;
    TXT: ResourceHandler<TXTRecordType>;
    SOA: ResourceHandler<SOARecordType>;
    SRV: ResourceHandler<SRVRecordType>;
    EDNS: typeof EDNSRecord & { ECS: typeof ECSOption };
    CAA: ResourceHandler<CAARecordType>;
    DNSKEY: ResourceHandler<DNSKeyRecordType>;
    RRSIG: ResourceHandler<RRSigRecordType>;
  };
  static Name = {
    COPY: 0xC0,
    decode(reader: ReaderInput): string {
      const source = asReader(reader);
      const name: string[] = [];
      let originalOffset: number | undefined;
      let length = source.read(8);

      while (length) {
        if ((length & Packet.Name.COPY) === Packet.Name.COPY) {
          length -= Packet.Name.COPY;
          length <<= 8;
          const position = length + source.read(8);
          if (originalOffset === undefined) {
            originalOffset = source.offset;
          }
          source.offset = position * 8;
          length = source.read(8);
          continue;
        }

        let part = '';
        while (length > 0) {
          part += String.fromCharCode(source.read(8));
          length -= 1;
        }
        name.push(part);
        length = source.read(8);
      }

      if (originalOffset !== undefined) {
        source.offset = originalOffset;
      }

      return name.join('.');
    },
    encode(domain: string | undefined, writer = new BufferWriter()): Buffer {
      (domain ?? '')
        .split('.')
        .filter(Boolean)
        .forEach((part) => {
          writer.write(part.length, 8);
          part.split('').forEach((character) => {
            writer.write(character.charCodeAt(0), 8);
          });
        });
      writer.write(0, 8);
      return writer.toBuffer();
    },
  };
  static uuid(): number {
    return Math.floor(Math.random() * 1e5);
  }
  static parse(buffer: Buffer): Packet {
    const packet = new Packet();
    const reader = new Packet.Reader(buffer);
    packet.header = Packet.Header.parse(reader);

    ([
      ['questions', Packet.Question, packet.header.qdcount],
      ['answers', Packet.Resource, packet.header.ancount],
      ['authorities', Packet.Resource, packet.header.nscount],
      ['additionals', Packet.Resource, packet.header.arcount],
    ] as const).forEach(([section, decoder, count]) => {
      let remaining = count;
      while (remaining > 0) {
        try {
          //TODO: make this type safe
          packet[section].push(decoder.parse(reader) as never);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          debug('node-dns > parse %s error:', section, message);
        }
        remaining -= 1;
      }
    });

    return packet;
  }
  static createResponseFromRequest(request: Packet): Packet {
    const response = new Packet(request);
    response.header.qr = 1;
    response.additionals = [];
    return response;
  }
  static createResourceFromQuestion(base: Partial<ResourceFields>, record: Partial<ResourceFields>): Resource {
    const resource = new Packet.Resource(base);
    Object.assign(resource, record);
    return resource;
  }
  static readStream(socket: NodeJS.ReadableStream & {
    read(): Buffer | null;
    on(event: 'end', listener: () => void): unknown;
    on(event: 'error', listener: (error: Error) => void): unknown;
    on(event: 'readable', listener: () => void): unknown;
  }): Promise<Buffer> {
    let chunks: Buffer[] = [];
    let chunkLength = 0;
    let received = false;
    let expected = 0;

    return new Promise((resolve, reject) => {
      const processMessage = () => {
        if (received) {
          return;
        }
        received = true;
        const buffer = Buffer.concat(chunks, chunkLength);
        resolve(buffer.slice(2));
      };

      socket.on('end', processMessage);
      socket.on('error', reject);
      socket.on('readable', () => {
        let chunk: Buffer | string | null;
        while ((chunk = socket.read()) !== null) {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          chunks.push(buffer);
          chunkLength += buffer.length;
        }

        if (!expected && chunkLength >= 2) {
          if (chunks.length > 1) {
            chunks = [Buffer.concat(chunks, chunkLength)];
          }
          expected = chunks[0].readUInt16BE(0);
        }

        if (chunkLength >= 2 + expected) {
          processMessage();
        }
      });
    });
  }

  constructor(data?: PacketInput) {
    this.header = new Header();
    this.questions = [];
    this.answers = [];
    this.authorities = [];
    this.additionals = [];

    if (data instanceof Packet) {
      this.header = new Header(data.header);
      this.questions = data.questions.map(question => new Question(question));
      this.answers = data.answers.map(answer => new Resource(answer));
      this.authorities = data.authorities.map(authority => new Resource(authority));
      this.additionals = data.additionals.map(additional => new Resource(additional));
      return;
    }

    if (data instanceof Header) {
      this.header = data;
      return;
    }

    if (data instanceof Question) {
      this.questions.push(data);
      return;
    }

    if (data instanceof Resource) {
      this.answers.push(data);
      return;
    }

    if (typeof data === 'string') {
      this.questions.push(new Question(data));
      return;
    }

    if (Array.isArray(data)) {
      this.questions = data.map(question => new Question(question));
      return;
    }

    if (data && typeof data === 'object') {
      this.header = new Header(data);
    }
  }

  get recursive(): boolean {
    return Boolean(this.header.rd);
  }

  set recursive(enabled: boolean) {
    this.header.rd = Number(enabled);
  }

  toBuffer(writer = new Packet.Writer()): Buffer {
    this.header.qdcount = this.questions.length;
    this.header.ancount = this.answers.length;
    this.header.nscount = this.authorities.length;
    this.header.arcount = this.additionals.length;
    if (!(this.header instanceof Packet.Header)) {
      this.header = new Packet.Header(this.header);
    }

    this.header.toBuffer(writer);
    ([
      ['questions', Packet.Question],
      ['answers', Packet.Resource],
      ['authorities', Packet.Resource],
      ['additionals', Packet.Resource],
    ] as const).forEach(([section, encoder]) => {
      this[section].forEach((resource) => {
        encoder.encode(resource , writer);
      });
    });

    return writer.toBuffer();
  }

  toBase64URL(): string {
    return this.toBuffer()
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }
}
