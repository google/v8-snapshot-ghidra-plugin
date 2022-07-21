/*
 * Copyright 2022 Google LLC Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package v8snapshot.loader;

import com.google.common.collect.ImmutableList;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public final class BytecodeLoader extends AbstractLibrarySupportLoader {
  private static final byte[] FILE_MAGIC = {(byte) 0xDE, (byte) 0xC0};
  private static final long FILE_MAGIC_LENGTH = 4;

  @Override
  public String getName() {
    return "V8 snapshot loader";
  }

  @Override
  public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
    ImmutableList.Builder<LoadSpec> loadSpecs = ImmutableList.builder();
    if (provider.length() < FILE_MAGIC_LENGTH) {
      return loadSpecs.build();
    }
    BinaryReader reader = new BinaryReader(provider, /* isLittleEndian= */true);
    // Only the high 16-bits are fixed.
    byte[] magicBytes = reader.readByteArray(2, 2);
    if (Arrays.equals(magicBytes, FILE_MAGIC)) {
      // TODO: Search the version hash for the exact v8 version.
      loadSpecs.add(new LoadSpec(this, 0,
          new LanguageCompilerSpecPair("v8.5:LE:32:default", "default"), true));
    }
    return loadSpecs.build();
  }

  @Override
  protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
      Program program, TaskMonitor monitor, MessageLog log) {
    throw new UnsupportedOperationException("Not implemented yet.");
  }

  @Override
  public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
      DomainObject domainObject, boolean isLoadIntoProgram) {
    List<Option> list =
        super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
    // TODO: If this loader has custom options, add them to 'list'
    list.add(new Option("Option name goes here", "Default option value goes here"));
    return list;
  }

  @Override
  public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
      Program program) {
    // TODO: If this loader has custom options, validate them here. Not all options
    // require validation.
    return super.validateOptions(provider, loadSpec, options, program);
  }
}
