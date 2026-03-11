import {GoogleClient} from '../../src/index.ts';

(async() => {
  const resolve = GoogleClient();
  const response = await resolve('google.com');
  console.log(response);
})();
