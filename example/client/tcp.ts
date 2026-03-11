import {TCPClient} from '../../src/index.ts';

const resolve = TCPClient();

(async() => {
  try {
    const response = await resolve('google.com');
    console.log(response.answers);
  } catch (error) {
    console.log(error);
  }
})();
