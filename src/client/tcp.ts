import * as net from 'node:net';
import * as tls from 'node:tls';
import type { Socket } from 'node:net';

import Packet, { CLASS } from '../packet.ts';
import type { ResolveFn, ResolveOptions } from './udp.ts';

export interface TcpClientOptions {
  dns?: string;
  protocol?: 'tcp:' | 'tls:';
  port?: number;
}

const makeQuery = ({
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
}): Buffer => {
  const packet = new Packet();
  packet.header.rd = recursive ? 1 : 0;

  if (clientIp) {
    packet.additionals.push(new Packet.Resource.EDNS([
      new Packet.Resource.EDNS.ECS(clientIp),
    ]));
  }

  packet.questions.push({ name, class: cls, type: Packet.TYPE[type] } as never);
  return packet.toBuffer();
};

const sendQuery = (client: Socket, message: Buffer): void => {
  const length = Buffer.alloc(2);
  length.writeUInt16BE(message.length);
  client.write(Buffer.concat([length, message]));
};

const protocols: Record<NonNullable<TcpClientOptions['protocol']>, (host: string, port: number) => Socket> = {
  'tcp:': (host, port) => net.connect({ host, port }),
  'tls:': (host, port) => tls.connect({ host, port, servername: host }),
};

const TCPClient = ({
  dns = '8.8.8.8',
  protocol = 'tcp:',
  port = protocol === 'tls:' ? 853 : 53,
}: TcpClientOptions = {}): ResolveFn => {
  if (!protocols[protocol]) {
    throw new Error('Protocol must be tcp: or tls:');
  }

  return async (name, type, cls, options: ResolveOptions = {}) => {
    const message = makeQuery({ name, type, cls, ...options });
    const [host] = dns.split(':');
    const client = protocols[protocol](host, port);

    sendQuery(client, message);
    const data = await Packet.readStream(client);
    client.end();

    if (!data.length) {
      throw new Error('Empty response');
    }
    return Packet.parse(data);
  };
};

export default TCPClient;
