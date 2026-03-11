import { EventEmitter } from 'node:events';

import Packet from './packet.ts';
import DOHClient from './client/doh.ts';
import GoogleClient from './client/google.ts';
import TCPClient from './client/tcp.ts';
import UDPClient from './client/udp.ts';
import {
  TCPServer,
  UDPServer,
  DOHServer,
  DNSServer,
  createTCPServer,
  createUDPServer,
  createDOHServer,
  createServer,
} from './server/index.ts';

export interface DNSOptions {
  port?: number;
  retries?: number;
  timeout?: number;
  recursive?: boolean;
  resolverProtocol?: 'UDP' | 'TCP' | 'DOH';
  nameServers?: string[];
  rootServers?: string[];
}

class DNS extends EventEmitter {
  port: number;
  retries: number;
  timeout: number;
  recursive: boolean;
  resolverProtocol: 'UDP' | 'TCP' | 'DOH';
  nameServers: string[];
  rootServers: string[];

  constructor(options: DNSOptions = {}) {
    super();
    this.port = 53;
    this.retries = 3;
    this.timeout = 3;
    this.recursive = true;
    this.resolverProtocol = 'UDP';
    this.nameServers = [
      '8.8.8.8',
      '114.114.114.114',
    ];
    this.rootServers = [
      'a', 'b', 'c', 'd', 'e', 'f',
      'g', 'h', 'i', 'j', 'k', 'l', 'm',
    ].map(value => `${value}.root-servers.net`);
    Object.assign(this, options);
  }

  resolve(domain: string, type: keyof typeof Packet.TYPE = 'ANY', cls = Packet.CLASS.IN, options = {}) {
    const { port, nameServers, resolverProtocol = 'UDP' } = this;
    const createResolver = DNS[`${resolverProtocol}Client`];
    return Promise.race(nameServers.map((address) => {
      const resolve = createResolver({ dns: address, port });
      return resolve(domain, type, cls, options);
    }));
  }

  resolveA(domain: string, clientIp?: string) {
    return this.resolve(domain, 'A', undefined, clientIp ? { clientIp } : {});
  }

  resolveAAAA(domain: string) {
    return this.resolve(domain, 'AAAA');
  }

  resolveMX(domain: string) {
    return this.resolve(domain, 'MX');
  }

  resolveCNAME(domain: string) {
    return this.resolve(domain, 'CNAME');
  }

  resolvePTR(domain: string) {
    return this.resolve(domain, 'PTR');
  }

  resolveDNSKEY(domain: string) {
    return this.resolve(domain, 'DNSKEY');
  }

  resolveRRSIG(domain: string) {
    return this.resolve(domain, 'RRSIG' as keyof typeof Packet.TYPE);
  }

  static TCPServer = TCPServer;
  static UDPServer = UDPServer;
  static DOHServer = DOHServer;
  static DNSServer = DNSServer;
  static createUDPServer = createUDPServer;
  static createTCPServer = createTCPServer;
  static createDOHServer = createDOHServer;
  static createServer = createServer;
  static TCPClient = TCPClient;
  static DOHClient = DOHClient;
  static UDPClient = UDPClient;
  static GoogleClient = GoogleClient;
  static Packet = Packet;
}

export {
  Packet,
  DOHClient,
  GoogleClient,
  TCPClient,
  UDPClient,
  TCPServer,
  UDPServer,
  DOHServer,
  DNSServer,
  createTCPServer,
  createUDPServer,
  createDOHServer,
  createServer,
};

export default DNS;
