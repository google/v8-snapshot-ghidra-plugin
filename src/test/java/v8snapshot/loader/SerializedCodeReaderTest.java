/*
 * Copyright 2022 Google LLC Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package v8snapshot.loader;

import static com.google.common.truth.Truth.assertThat;
import org.junit.Test;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

public class SerializedCodeReaderTest {
  @Test
  public void getByte_returnsByte() throws Exception {
    byte[] data = {(byte) 0xFF, (byte) 0xFF, (byte) 0x01, (byte) 0x02};
    ByteProvider provider = new ByteArrayProvider(data);
    SerializedCodeReader reader = new SerializedCodeReader(provider, 2);

    byte firstByte = reader.getByte();
    byte secondByte = reader.getByte();

    assertThat(firstByte).isEqualTo((byte) 0x01);
    assertThat(secondByte).isEqualTo((byte) 0x02);
  }

  @Test
  public void getBytes_returnsByteArray() throws Exception {
    byte[] data = {(byte) 0xFF, (byte) 0xFF, (byte) 0x01, (byte) 0x02};
    ByteProvider provider = new ByteArrayProvider(data);
    SerializedCodeReader reader = new SerializedCodeReader(provider, 2);

    byte[] bytes = reader.getBytes(2);

    byte[] expectedData = {(byte) 0x01, (byte) 0x02};
    assertThat(bytes).isEqualTo(expectedData);
  }

  @Test
  public void getInt_returnsDecodedInt() throws Exception {
    byte[] data = {(byte) 0xFF, (byte) 0xFF,
        // Expect 0x01
        (byte) (0x00 | 0x01 << 2),
        // Expect 0x41
        (byte) (0x01 | 0x01 << 2), (byte) (0x01),
        // Expect 0x4041
        (byte) (0x02 | 0x01 << 2), (byte) (0x01), (byte) (0x01),
        // Expect 0x404041
        (byte) (0x03 | 0x01 << 2), (byte) (0x01), (byte) (0x01), (byte) (0x01)};
    ByteProvider provider = new ByteArrayProvider(data);
    SerializedCodeReader reader = new SerializedCodeReader(provider, 2);

    int oneByte = reader.getInt();
    int twoBytes = reader.getInt();
    int threeBytes = reader.getInt();
    int fourBytes = reader.getInt();

    assertThat(oneByte).isEqualTo(0x01);
    assertThat(twoBytes).isEqualTo(0x41);
    assertThat(threeBytes).isEqualTo(0x4041);
    assertThat(fourBytes).isEqualTo(0x404041);
  }
}
