export default class BufferWriter {
  buffer: number[];

  constructor() {
    this.buffer = [];
  }

  write(value: number, size: number): void {
    for (let i = 0; i < size; i += 1) {
      this.buffer.push((value & (2 ** (size - i - 1))) ? 1 : 0);
    }
  }

  writeBuffer(writer: BufferWriter): void {
    this.buffer = this.buffer.concat(writer.buffer);
  }

  toBuffer(): Buffer {
    const bytes: number[] = [];
    for (let i = 0; i < this.buffer.length; i += 8) {
      const chunk = this.buffer.slice(i, i + 8);
      bytes.push(Number.parseInt(chunk.join(''), 2));
    }
    return Buffer.from(bytes);
  }
}
