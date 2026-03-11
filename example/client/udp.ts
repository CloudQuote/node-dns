import {UDPClient} from "../../src/index.ts";

const resolve = UDPClient();

(async() => {
  const response = await resolve('google.com');
  console.log(response.answers);
})();
