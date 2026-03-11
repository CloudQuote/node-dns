import { createSocket, type BindOptions, type RemoteInfo, type Socket, type SocketType } from 'node:dgram';
import { EventEmitter } from 'node:events';

import Packet from '../packet.ts';

export type RequestHandler = (request: Packet, send: (message: Packet | Buffer) => Promise<Buffer>, client: RemoteInfo) => void;

export interface UdpServerOptions {
  type?: SocketType;
}

export default class Server extends EventEmitter {
  socket: Socket;

  constructor(options?: UdpServerOptions | RequestHandler) {
    super();
    let type: SocketType = 'udp4';
    if (typeof options === 'object' && options) {
      type = options.type ?? type;
    }
    this.socket = createSocket(type);
    if (typeof options === 'function') {
      this.on('request', options);
    }
    this.socket.on('message', this.handle.bind(this));
    this.socket.on('listening', () => this.emit('listening'));
    this.socket.on('close', () => this.emit('close'));
    this.socket.on('error', error => this.emit('error', error));
  }

  handle(data: Buffer, rinfo: RemoteInfo): void {
    try {
      const message = Packet.parse(data);
      this.emit('request', message, this.response.bind(this, rinfo), rinfo);
    } catch (error) {
      this.emit('requestError', error);
    }
  }

  response(rinfo: RemoteInfo, message: Packet | Buffer): Promise<Buffer> {
    const payload = message instanceof Packet ? message.toBuffer() : message;
    return new Promise((resolve, reject) => {
      this.socket.send(payload, rinfo.port, rinfo.address, (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(payload);
      });
    });
  }

  listen(port?: number, address?: string): Promise<void> {
    return new Promise(resolve => this.socket.bind(port, address, resolve));
  }

  bind(port?: number | BindOptions | (() => void), address?: string | (() => void), callback?: () => void): this {
    if (typeof port === 'function') {
      this.socket.bind(port);
      return this;
    }
    if (typeof address === 'function') {
      if (typeof port === 'object' && port !== null) {
        this.socket.bind(port, address);
      } else {
        this.socket.bind(port as number | undefined, address);
      }
      return this;
    }
    if (typeof port === 'object' && port !== null) {
      this.socket.bind(port, callback);
      return this;
    }
    this.socket.bind(port as number | undefined, address as string | undefined, callback);
    return this;
  }

  send(...args: Parameters<Socket['send']>): ReturnType<Socket['send']> {
    return this.socket.send(...args);
  }

  address() {
    return this.socket.address();
  }

  close(callback?: () => void): this {
    this.socket.close(callback);
    return this;
  }

  connect(...args: Parameters<Socket['connect']>): ReturnType<Socket['connect']> {
    return this.socket.connect(...args);
  }

  disconnect(): void {
    this.socket.disconnect();
  }

  ref(): this {
    this.socket.ref();
    return this;
  }

  unref(): this {
    this.socket.unref();
    return this;
  }

  addMembership(...args: Parameters<Socket['addMembership']>): void {
    this.socket.addMembership(...args);
  }

  dropMembership(...args: Parameters<Socket['dropMembership']>): void {
    this.socket.dropMembership(...args);
  }

  addSourceSpecificMembership(...args: Parameters<Socket['addSourceSpecificMembership']>): void {
    this.socket.addSourceSpecificMembership(...args);
  }

  dropSourceSpecificMembership(...args: Parameters<Socket['dropSourceSpecificMembership']>): void {
    this.socket.dropSourceSpecificMembership(...args);
  }

  setBroadcast(flag: boolean): void {
    this.socket.setBroadcast(flag);
  }

  setTTL(ttl: number): number {
    return this.socket.setTTL(ttl);
  }

  setMulticastTTL(ttl: number): number {
    return this.socket.setMulticastTTL(ttl);
  }

  setMulticastLoopback(flag: boolean): void {
    this.socket.setMulticastLoopback(flag);
  }

  setMulticastInterface(multicastInterface: string): void {
    this.socket.setMulticastInterface(multicastInterface);
  }

  getRecvBufferSize(): number {
    return this.socket.getRecvBufferSize();
  }

  getSendBufferSize(): number {
    return this.socket.getSendBufferSize();
  }

  setRecvBufferSize(size: number): void {
    this.socket.setRecvBufferSize(size);
  }

  setSendBufferSize(size: number): void {
    this.socket.setSendBufferSize(size);
  }
}
