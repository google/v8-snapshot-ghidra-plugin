/*
 * Copyright 2022 Google LLC Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package v8snapshot.versiondeps.v85;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.junit.*;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import v8snapshot.loader.SnapshotMetadata;

public class VersionLoaderProviderTest {

  private final VersionLoaderProvider.Builder providerBuilder = new VersionLoaderProvider.Builder();

  @Test
  public void getMetadata_success() throws Exception {
    ByteBuffer header = ByteBuffer.allocate(148).order(ByteOrder.LITTLE_ENDIAN);
    // Num of stubs = 3.
    header.putInt(16, 3);
    // Payload length = 100.
    header.putInt(20, 100);
    ByteProvider byteProvider = new ByteArrayProvider(header.array());
    v8snapshot.loader.VersionLoaderProvider loaderProvider = providerBuilder.build(byteProvider,
        new LanguageCompilerSpecPair("v8.5:LE:64:compact", "default"));

    SnapshotMetadata metadata = loaderProvider.getMetadata();

    assertThat(metadata).isEqualTo(SnapshotMetadata.builder().setNumOfStubs(3).setPayloadLength(100)
        .setPayloadOffset(48).setSlotDataSize(4).build());
  }

  @Test
  public void buildProvider_notFound() throws Exception {
    ByteProvider byteProvider = new ByteArrayProvider(new byte[10]);
    LanguageCompilerSpecPair unknownLangSpec =
        new LanguageCompilerSpecPair("v9.5:LE:64:compact", "unknown");

    assertThrows(UnsupportedOperationException.class, () -> {
      providerBuilder.build(byteProvider, unknownLangSpec);
    });
  }
}
