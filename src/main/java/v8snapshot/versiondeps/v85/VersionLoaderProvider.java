/*
 * Copyright 2022 Google LLC Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package v8snapshot.versiondeps.v85;

import java.io.IOException;
import com.google.common.collect.ImmutableSet;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import v8snapshot.loader.SnapshotMetadata;

/** Provides the helpers to load v8.5 snapshot. */
public class VersionLoaderProvider implements v8snapshot.loader.VersionLoaderProvider {
  private static final int HEADER_LENGTH = 32;
  private static final int NUM_OF_STUBS_HEADER_OFFSET = 16;
  private static final int PAYLOAD_LENGTH_HEADER_OFFSET = 20;

  private final BinaryReader reader;
  private final int stubSize;
  private final int pointerSize;
  private final int slotDataSize;

  VersionLoaderProvider(BinaryReader reader, int stubSize, int pointerSize, int slotDataSize) {
    this.reader = reader;
    this.stubSize = stubSize;
    this.pointerSize = pointerSize;
    this.slotDataSize = slotDataSize;
  }

  @Override
  public SnapshotMetadata getMetadata() throws IOException {
    int numOfStubs = reader.readInt(NUM_OF_STUBS_HEADER_OFFSET);
    int payloadLength = reader.readInt(PAYLOAD_LENGTH_HEADER_OFFSET);
    long headerAndStubSize = HEADER_LENGTH + numOfStubs * stubSize;
    // Align with the pointer size.
    long payloadOffset = (headerAndStubSize + pointerSize - 1) / pointerSize * pointerSize;
    if (payloadOffset + payloadLength > reader.length()) {
      throw new AssertionError(
          String.format("Payload length: %d is larger than actual file size: %d.",
              payloadOffset + payloadLength, reader.length()));
    }
    return SnapshotMetadata.builder().setNumOfStubs(numOfStubs).setPayloadLength(payloadLength)
        .setPayloadOffset(payloadOffset).setSlotDataSize(slotDataSize).build();
  }

  public static final class Builder implements v8snapshot.loader.VersionLoaderProvider.Builder {

    private static final LanguageCompilerSpecPair LE_64_COMPACT_SPEC =
        new LanguageCompilerSpecPair("v8.5:LE:64:compact", "default");
    private static final ImmutableSet<LanguageCompilerSpecPair> SUPPORTED_SPECS =
        ImmutableSet.of(LE_64_COMPACT_SPEC);

    @Override
    public ImmutableSet<LanguageCompilerSpecPair> getSupportedSpecs() {
      return SUPPORTED_SPECS;
    }

    @Override
    public v8snapshot.loader.VersionLoaderProvider build(ByteProvider byteProvider,
        LanguageCompilerSpecPair langSpec) {
      int stubSize;
      int pointerSize;
      int slotDataSize;
      boolean isLittleEndian;

      if (langSpec.equals(LE_64_COMPACT_SPEC)) {
        stubSize = 4;
        pointerSize = 8;
        slotDataSize = 4;
        isLittleEndian = true;
      } else {
        throw new UnsupportedOperationException(
            String.format("Unsupported language spec: '%s'.", langSpec));
      }

      return new VersionLoaderProvider(new BinaryReader(byteProvider, isLittleEndian), stubSize,
          pointerSize, slotDataSize);
    }
  }
}
