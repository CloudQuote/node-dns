import * as https from 'node:https';

export interface GoogleResolveResponse {
  Status: number;
  Answer?: Array<Record<string, unknown>>;
  Question?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

const get = (url: string): Promise<import('node:http').IncomingMessage> => new Promise(resolve => https.get(url, resolve));

const readStream = (stream: NodeJS.ReadableStream): Promise<Buffer> => {
  const buffer: Buffer[] = [];
  return new Promise((resolve, reject) => {
    stream
      .on('error', reject)
      .on('data', (chunk: Buffer | string) => {
        buffer.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      })
      .on('end', () => resolve(Buffer.concat(buffer)));
  });
};

const GoogleClient = () => (
  async (name: string, type = 'ANY'): Promise<GoogleResolveResponse> => JSON.parse(
    (await readStream(await get(`https://dns.google.com/resolve?name=${name}&type=${type}`))).toString(),
  ) as GoogleResolveResponse
);

export default GoogleClient;
