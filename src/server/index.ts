import UDPServer from './udp.ts';
import TCPServer from './tcp.ts';
import DOHServer from './doh.ts';
import DNSServer from './dns.ts';

const createUDPServer = (options?: ConstructorParameters<typeof UDPServer>[0]): UDPServer => new UDPServer(options);
const createTCPServer = (options?: ConstructorParameters<typeof TCPServer>[0]): TCPServer => new TCPServer(options);
const createDOHServer = (options?: ConstructorParameters<typeof DOHServer>[0]): DOHServer => new DOHServer(options);
const createServer = (options?: ConstructorParameters<typeof DNSServer>[0]): DNSServer => new DNSServer(options);

export {
  UDPServer,
  TCPServer,
  DOHServer,
  DNSServer,
  createTCPServer,
  createUDPServer,
  createDOHServer,
  createServer,
};
