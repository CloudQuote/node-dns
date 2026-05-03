import { createSocket } from 'node:dgram';
import { equal } from 'node:assert';
import { debuglog } from 'node:util';

import Packet, { CLASS } from '../packet.ts';

const debug = debuglog('dns2');

export interface ResolveOptions {
  clientIp?: string;
  recursive?: boolean;
}

export interface UdpClientOptions {
  dns?: string;
  port?: number;
  socketType?: 'udp4' | 'udp6';
}

export type ResolveFn = (
  name: string,
  type?: keyof typeof Packet.TYPE,
  cls?: number,
  options?: ResolveOptions,
) => Promise<Packet>;

const UDPClient = ({ dns = '8.8.8.8', port = 53, socketType = 'udp4' }: UdpClientOptions = {}): ResolveFn => {
  return (name, type = 'A', cls = CLASS.IN, options = {}) => {
    const { clientIp, recursive = true } = options;
    const query = new Packet();
    query.header.id = (Math.random() * 1e4) | 0;
    if (recursive) {
      query.header.rd = 1;
    }
    if (clientIp) {
      query.additionals.push(new Packet.Resource.EDNS([
        new Packet.Resource.EDNS.ECS(clientIp),
      ]));
    }
    query.questions.push({
      name,
      class: cls,
      type: Packet.TYPE[type],
    });

    const client = createSocket(socketType);
    return new Promise((resolve, reject) => {
      client.once('message', (message) => {
        client.close();
        const response = Packet.parse(message);
        equal(response.header.id, query.header.id);
        resolve(response);
      });
      debug('send', dns, query.toBuffer());
      client.send(query.toBuffer(), port, dns, (error) => {
        if (error) {
          reject(error);
        }
      });
    });
  };
};

export default UDPClient;
