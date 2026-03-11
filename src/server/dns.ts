import { EventEmitter } from 'node:events';

import DOHServer, { type DohServerOptions } from './doh.ts';
import TCPServer from './tcp.ts';
import UDPServer, { type UdpServerOptions } from './udp.ts';

type ClosableServer = EventEmitter & {
  address(): unknown;
  close(): unknown;
  listen(port?: number, address?: string): unknown;
};

export interface DnsServerOptions {
  doh?: boolean | DohServerOptions;
  tcp?: boolean;
  udp?: boolean | UdpServerOptions;
  handle?: (...args: unknown[]) => void;
}

type ServerMap = {
  doh?: ClosableServer;
  tcp?: ClosableServer;
  udp?: ClosableServer;
};

type ServerAddressMap = {
  udp?: ReturnType<ClosableServer['address']>;
  tcp?: ReturnType<ClosableServer['address']>;
  doh?: ReturnType<ClosableServer['address']>;
};

export default class DNSServer extends EventEmitter {
  servers: ServerMap;
  closed: Promise<void>;
  listening: Promise<ServerAddressMap>;

  constructor(options: DnsServerOptions = {}) {
    super();
    this.servers = {};

    if (options.doh) {
      const dohOptions = typeof options.doh === 'object' ? options.doh : {};
      this.servers.doh = new DOHServer(dohOptions)
        .on('error', error => this.emit('error', error, 'doh'));
    }
    if (options.tcp) {
      this.servers.tcp = new TCPServer()
        .on('error', error => this.emit('error', error, 'tcp'));
    }
    if (options.udp) {
      const udpOptions = typeof options.udp === 'object' ? options.udp : undefined;
      this.servers.udp = new UDPServer(udpOptions)
        .on('error', error => this.emit('error', error, 'udp'));
    }

    const servers = Object.values(this.servers).filter((server): server is ClosableServer => Boolean(server));
    this.closed = Promise.all(servers.map(server => new Promise<void>(resolve => server.once('close', () => resolve()))))
      .then(() => {
        this.emit('close');
      });

    this.listening = Promise.all(servers.map(server => new Promise<void>(resolve => server.once('listening', () => resolve()))))
      .then(() => {
        const addresses = this.addresses();
        this.emit('listening', addresses);
        return addresses;
      });

    const emitRequest = (...args: unknown[]) => this.emit('request', ...args);
    const emitRequestError = (error: Error) => this.emit('requestError', error);
    for (const server of servers) {
      server.on('request', emitRequest);
      server.on('requestError', emitRequestError);
    }

    if (options.handle) {
      this.on('request', options.handle.bind(options));
    }
  }

  addresses(): ServerAddressMap {
    const addresses: ServerAddressMap = {};
    if (this.servers.udp) {
      addresses.udp = this.servers.udp.address();
    }
    if (this.servers.tcp) {
      addresses.tcp = this.servers.tcp.address();
    }
    if (this.servers.doh) {
      addresses.doh = this.servers.doh.address();
    }
    return addresses;
  }

  listen(options: {
    udp?: number | { port?: number; address?: string };
    tcp?: number | { port?: number; address?: string };
    doh?: number | { port?: number; address?: string };
  } = {}): Promise<ServerAddressMap> {
    for (const serverType of Object.keys(this.servers) as Array<keyof ServerMap>) {
      const server = this.servers[serverType];
      const serverOptions = options[serverType];

      if (!server) {
        continue;
      }

      if (typeof serverOptions === 'object' && serverOptions?.port !== undefined) {
        server.listen(serverOptions.port, serverOptions.address);
      } else {
        server.listen(serverOptions as number | undefined);
      }
    }

    return this.listening;
  }

  close(): Promise<void> {
    this.servers.udp?.close();
    this.servers.tcp?.close();
    this.servers.doh?.close();
    return this.closed;
  }
}
