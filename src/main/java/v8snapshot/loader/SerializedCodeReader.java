/*
 * Copyright 2022 Google LLC Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package v8snapshot.loader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/** Reader that tracks the next position and decode variable-length integers. */
public final class SerializedCodeReader {

  private static final int BITS_OF_LENGTH = 2;
  private static final int LENGTH_MASK = (1 << BITS_OF_LENGTH) - 1;
  private static final int BITS_OF_BYTE = 8;

  private final BinaryReader reader;

  public SerializedCodeReader(ByteProvider provider, long startOffset) throws IOException {
    this.reader = new BinaryReader(provider, /* isLittleEndian= */true);
    if (startOffset >= this.reader.length()) {
      throw new AssertionError(String.format("The offset %d exceeds the file size %d.", startOffset,
          this.reader.length()));
    }
    this.reader.setPointerIndex(startOffset);
  }

  public byte getByte() throws IOException {
    return (byte) (reader.readNextByte() & 0xFF);
  }

  public byte[] getBytes(int length) throws IOException {
    return reader.readNextByteArray(length);
  }

  /**
   * Decodes variable-length integer encoding.
   *
   * <p>
   * Reference:
   * https://chromium.googlesource.com/v8/v8/+/1344651e26b8e6dece590c7991ad5f29cc940ddc/src/snapshot/snapshot-source-sink.h#82
   */
  public int getInt() throws IOException {
    int answer = getByte();
    int length = (answer & LENGTH_MASK) + 1;
    for (int off = 1; off < length; off++) {
      answer |= getByte() << (off * BITS_OF_BYTE);
    }
    return answer >> BITS_OF_LENGTH;
  }
}
