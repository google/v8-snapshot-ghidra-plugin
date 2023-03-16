/*
 * Copyright 2022 Google LLC Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package v8snapshot.loader;

import com.google.auto.value.AutoValue;

/** Parameters of a snapshot. */
@AutoValue
public abstract class SnapshotMetadata {
  public abstract int numOfStubs();

  public abstract int payloadLength();

  public abstract long payloadOffset();

  public abstract int slotDataSize();

  public static Builder builder() {
    return new AutoValue_SnapshotMetadata.Builder();
  }

  @AutoValue.Builder
  public static abstract class Builder {
    public abstract Builder setNumOfStubs(int numOfStubs);

    public abstract Builder setPayloadLength(int payloadLength);

    public abstract Builder setPayloadOffset(long payloadOffset);

    public abstract Builder setSlotDataSize(int slotDataSize);

    public abstract SnapshotMetadata build();
  }
}
