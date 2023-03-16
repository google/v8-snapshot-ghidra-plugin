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
import org.junit.*;
import com.google.common.collect.ImmutableList;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

public class BytecodeLoaderTest {
  @Test
  public void findSupportedLoadSpecs_match() throws Exception {
    BytecodeLoader loader = new BytecodeLoader();
    byte[] header = {(byte) 0xEF, (byte) 0xBE, (byte) 0xDE, (byte) 0xC0};
    ByteProvider provider = new ByteArrayProvider(header);

    ImmutableList<LoadSpec> specs = ImmutableList.copyOf(loader.findSupportedLoadSpecs(provider));

    assertThat(specs.size()).isEqualTo(1);
    assertThat(specs.get(0).getLanguageCompilerSpec())
        .isEqualTo(new LanguageCompilerSpecPair("v8.5:LE:64:compact", "default"));
  }

  @Test
  public void findSupportedLoadSpecs_notMatch() throws Exception {
    BytecodeLoader loader = new BytecodeLoader();
    byte[] header = {(byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};
    ByteProvider provider = new ByteArrayProvider(header);

    ImmutableList<LoadSpec> specs = ImmutableList.copyOf(loader.findSupportedLoadSpecs(provider));

    assertThat(specs).isEmpty();
  }
}
