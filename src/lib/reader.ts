export default class BufferReader {
  buffer: Buffer;
  offset: number;

  constructor(buffer: Buffer, offset = 0) {
    this.buffer = buffer;
    this.offset = offset;
  }

  static read(buffer: Buffer, offset: number, length: number): number {
    let bits: number[] = [];
    let byteCount = Math.ceil(length / 8);
    let byteOffset = Math.floor(offset / 8);
    const bitOffset = offset % 8;

    const pushByte = (value: number) => {
      const nextBits = Array.from({ length: 8 }, (_, index) => ((value & (1 << (7 - index))) ? 1 : 0));
      bits = bits.concat(nextBits);
    };

    const parseBits = (values: number[]) => {
      let total = 0;
      const lastIndex = values.length - 1;
      for (let i = lastIndex; i >= 0; i -= 1) {
        if (values[lastIndex - i]) {
          total += 2 ** i;
        }
      }
      return total;
    };

    while (byteCount > 0) {
      pushByte(buffer.readUInt8(byteOffset));
      byteOffset += 1;
      byteCount -= 1;
    }

    return parseBits(bits.slice(bitOffset, bitOffset + length));
  }

  read(size: number): number {
    const value = BufferReader.read(this.buffer, this.offset, size);
    this.offset += size;
    return value;
  }
}
