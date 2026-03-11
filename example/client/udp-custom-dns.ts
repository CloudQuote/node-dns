import dns from 'dns';
import {UDPClient} from '../../src/index.ts';

const resolve = UDPClient({
  dns: dns.getServers()[0],
});

(async() => {
  const response = await resolve('google.com');
  console.log(response.answers);
})();
