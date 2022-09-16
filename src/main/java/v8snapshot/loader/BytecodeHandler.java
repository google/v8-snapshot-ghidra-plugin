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

/** Handler that parses and processes a bytecode instruction. */
public interface BytecodeHandler<T extends BytecodeObject> {
  /**
   * Decodes the bytecode and fills the decoded data into the slots of bytecode object.
   *
   * @param bytecode the bytecode
   * @param bytecodeObject the bytecode object to hold decoded data
   * @param currentSlotIndex the start slot index to place the decoded data
   * @param reader the bytecode reader
   * @return the number of slots being filled.
   */
  int process(int bytecode, T bytecodeObject, int currentSlotIndex, SerializedCodeReader reader)
      throws IOException;
}
