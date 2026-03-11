import { Server as NetServer, type Socket } from 'node:net';

import Packet from '../packet.ts';

export type TcpRequestHandler = (request: Packet, send: (message: Packet | Buffer) => void, client: Socket) => void;

export default class Server extends NetServer {
  constructor(options?: TcpRequestHandler) {
    super();
    if (typeof options === 'function') {
      this.on('request', options);
    }
    this.on('connection', this.handle.bind(this));
  }

  async handle(client: Socket): Promise<void> {
    try {
      const data = await Packet.readStream(client);
      const message = Packet.parse(data);
      this.emit('request', message, this.response.bind(this, client), client);
    } catch (error) {
      this.emit('requestError', error);
      client.destroy();
    }
  }

  response(client: Socket, message: Packet | Buffer): void {
    const payload = message instanceof Packet ? message.toBuffer() : message;
    const length = Buffer.alloc(2);
    length.writeUInt16BE(payload.length);
    client.end(Buffer.concat([length, payload]));
  }
}
