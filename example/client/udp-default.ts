import DNS from '../../src/index.ts';

const dns = new DNS();

(async() => {
  const result = await dns.resolveA('google.com');
  console.log(result.answers);
})();
