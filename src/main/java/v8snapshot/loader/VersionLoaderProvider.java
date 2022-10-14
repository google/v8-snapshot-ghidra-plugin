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
import com.google.common.collect.ImmutableSet;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

/** Provides the version-dependent helpers to assist the generic loader. */
public interface VersionLoaderProvider {
  SnapshotMetadata getMetadata() throws IOException;

  /** Builder of the version-dependent provider. */
  public interface Builder {
    ImmutableSet<LanguageCompilerSpecPair> getSupportedSpecs();

    VersionLoaderProvider build(ByteProvider byteProvider, LanguageCompilerSpecPair langSpec);
  }
}
