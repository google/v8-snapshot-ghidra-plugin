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
import java.util.ArrayList;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

/** Visitor that scans the bytecode and track the states. */
public final class BytecodeVisitor<T extends BytecodeObject> {

  private final SerializedCodeReader reader;
  private final BytecodeObject.Factory<T> objectFactory;
  private final ImmutableList<BytecodeRangeHandler<T>> bytecodeRangeHandlers;
  private final ArrayList<T> allObjects;

  public BytecodeVisitor(SerializedCodeReader reader, BytecodeObject.Factory<T> objectFactory,
      ImmutableList<BytecodeRangeHandler<T>> bytecodeRangeHandlers) {
    this.reader = reader;
    this.objectFactory = objectFactory;
    this.bytecodeRangeHandlers = bytecodeRangeHandlers;
    this.allObjects = new ArrayList<>();
  }

  public T visitObject(int spaceId, int numOfSlots) throws IOException {
    T object = objectFactory.create(spaceId, numOfSlots);;
    int currentSlotIndex = 0;
    while (currentSlotIndex < numOfSlots) {
      int bytecode = reader.getByte();
      BytecodeRangeHandler<T> foundRangeHandler = bytecodeRangeHandlers.stream()
          .filter(rangeHandler -> rangeHandler.start() <= bytecode && rangeHandler.end() > bytecode)
          .findFirst().orElseThrow(
              () -> new UnsupportedOperationException(String.format("bytecode: %x", bytecode)));
      currentSlotIndex +=
          foundRangeHandler.handler().process(bytecode, object, currentSlotIndex, reader);
    }
    allObjects.add(object);
    return object;
  }

  public ImmutableList<T> getAllObjects() {
    return ImmutableList.copyOf(allObjects);
  }

  /** Defines the bytecode range and its {@link BytecodeHandler}. */
  @AutoValue
  public static abstract class BytecodeRangeHandler<U extends BytecodeObject> {

    // Inclusive bytecode start.
    public abstract int start();

    // Exclusive bytecode end.
    public abstract int end();

    // Bytecode handler.
    public abstract BytecodeHandler<U> handler();

    public static <V extends BytecodeObject> BytecodeRangeHandler<V> create(int start, int end,
        BytecodeHandler<V> handler) {
      return new AutoValue_BytecodeVisitor_BytecodeRangeHandler<V>(start, end, handler);
    }
  }
}
