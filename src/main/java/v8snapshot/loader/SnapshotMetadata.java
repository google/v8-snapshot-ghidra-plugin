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
