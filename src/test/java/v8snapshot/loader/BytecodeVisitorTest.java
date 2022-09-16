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
import static org.junit.Assert.assertThrows;
import java.io.IOException;
import java.util.ArrayList;
import org.junit.Test;
import com.google.common.collect.ImmutableList;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

public final class BytecodeVisitorTest {

  @Test
  public void visitObject_succeeds() throws Exception {
    FakeBytecodeObject.Factory objectFactory = new FakeBytecodeObject.Factory();
    ImmutableList<BytecodeVisitor.BytecodeRangeHandler<FakeBytecodeObject>> handlers =
        ImmutableList.of(
            BytecodeVisitor.BytecodeRangeHandler.<FakeBytecodeObject>create(/* start= */0,
                /* end= */4, new FakeBytecodeHandler(/* handlerId= */10)),
            BytecodeVisitor.BytecodeRangeHandler.<FakeBytecodeObject>create(/* start= */4,
                /* end= */5, new FakeBytecodeHandler(/* handlerId= */20)));
    byte[] data = {(byte) 3, (byte) 11, (byte) 4, (byte) 22};
    ByteProvider provider = new ByteArrayProvider(data);
    SerializedCodeReader reader = new SerializedCodeReader(provider, /* startOffset= */0);
    BytecodeVisitor<FakeBytecodeObject> visitor =
        new BytecodeVisitor<>(reader, objectFactory, handlers);

    FakeBytecodeObject resultObject = visitor.visitObject(/* spaceId= */1, /* numOfSlots= */4);

    // Handler ids are stored in even slots and values are stored in odd slots.
    assertThat(resultObject.getSlots()).containsExactly(10, 11, 20, 22).inOrder();
  }

  @Test
  public void visitObject_bytecodeNotFound_throwsException() throws Exception {
    FakeBytecodeObject.Factory objectFactory = new FakeBytecodeObject.Factory();
    ImmutableList<BytecodeVisitor.BytecodeRangeHandler<FakeBytecodeObject>> handlers =
        ImmutableList.of(BytecodeVisitor.BytecodeRangeHandler.<FakeBytecodeObject>create(
            /* start= */0, /* end= */4, new FakeBytecodeHandler(/* handlerId= */11)));
    byte[] data = {(byte) 23};
    ByteProvider provider = new ByteArrayProvider(data);
    SerializedCodeReader reader = new SerializedCodeReader(provider, /* startOffset= */0);
    BytecodeVisitor<FakeBytecodeObject> visitor =
        new BytecodeVisitor<>(reader, objectFactory, handlers);

    assertThrows(UnsupportedOperationException.class,
        () -> visitor.visitObject(/* spaceId= */1, /* numOfSlots= */1));
  }

  /** Fake bytecode handler that populates slots with handler id and 1 byte value. */
  public static final class FakeBytecodeHandler implements BytecodeHandler<FakeBytecodeObject> {

    private final int handlerId;

    /**
     * Constructs the handler with a handler id.
     *
     * <p>
     * The handler id will be stored in the slots and helps tests distinguish the different
     * handlers.
     */
    public FakeBytecodeHandler(int handlerId) {
      this.handlerId = handlerId;
    }

    @Override
    public int process(int bytecode, FakeBytecodeObject bytecodeObject, int currentSlotIndex,
        SerializedCodeReader reader) throws IOException {
      bytecodeObject.setSlotValue(currentSlotIndex, handlerId);
      bytecodeObject.setSlotValue(currentSlotIndex + 1, reader.getByte());
      return 2;
    }
  }

  /** Fake bytecode object that stores and returns the slot values. */
  public static final class FakeBytecodeObject implements BytecodeObject {

    private final int spaceId;
    private final ArrayList<Integer> slots;

    public void setSlotValue(int slotIndex, int value) {
      slots.set(slotIndex, value);
    }

    public int getSpaceId() {
      return spaceId;
    }

    public ImmutableList<Integer> getSlots() {
      return ImmutableList.copyOf(slots);
    }

    public static final class Factory implements BytecodeObject.Factory<FakeBytecodeObject> {

      @Override
      public FakeBytecodeObject create(int spaceId, int numOfSlots) {
        return new FakeBytecodeObject(spaceId, numOfSlots);
      }
    }

    private FakeBytecodeObject(int spaceId, int numOfSlots) {
      this.spaceId = spaceId;
      this.slots = new ArrayList<>();
      for (int i = 0; i < numOfSlots; i++) {
        this.slots.add(0);
      }
    }
  }
}
