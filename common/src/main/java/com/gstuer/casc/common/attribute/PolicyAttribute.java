package com.gstuer.casc.common.attribute;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.gstuer.casc.common.cryptography.Signable;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

public abstract class PolicyAttribute<T> implements Signable, Serializable {
    @Serial
    private static final long serialVersionUID = -8322128904857578281L;

    private final AttributeIdentifier identifier;
    private final Duration validityDuration;
    private Instant validFrom;
    private T value;

    /**
     * The supplier of the value of this attribute, which is how the publishing AASP obtains the value from the
     * source of the attribute. It is a local concern of that AASP and therefore not part of the transmitted
     * attribute, which carries the value the AASP vouches for rather than the way it was obtained.
     */
    private transient Supplier<T> valueSupplier;

    public PolicyAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, T value) {
        this.identifier = Objects.requireNonNull(identifier);
        this.validFrom = Objects.requireNonNull(validFrom);
        this.validityDuration = Objects.requireNonNull(validityDuration);
        this.value = Objects.requireNonNull(value);
    }

    public PolicyAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Supplier<T> valueSupplier) {
        this.identifier = Objects.requireNonNull(identifier);
        this.validFrom = Objects.requireNonNull(validFrom);
        this.validityDuration = Objects.requireNonNull(validityDuration);
        this.value = valueSupplier.get();
        this.valueSupplier = valueSupplier;
    }

    public AttributeIdentifier getIdentifier() {
        return this.identifier;
    }

    public Instant getValidFrom() {
        return this.validFrom;
    }

    public Instant getValidUntil() {
        return this.validFrom.plus(validityDuration);
    }

    public Duration getValidityDuration() {
        return this.validityDuration;
    }

    public T getValue() {
        return this.value;
    }

    public abstract byte[] getValueAsBytes();

    public void setValueSupplier(Supplier<T> valueSupplier) {
        this.valueSupplier = valueSupplier;
    }

    public boolean hasValueSupplier() {
        return Objects.nonNull(this.valueSupplier);
    }

    public void update(T value) {
        this.value = Objects.requireNonNull(value);
        this.validFrom = Instant.now();
    }

    public void update() {
        if (this.valueSupplier == null) {
            throw new IllegalStateException("Cannot update value without supplier being set.");
        }
        this.update(this.valueSupplier.get());
    }

    /**
     * Checks whether this attribute is currently valid. An attribute is valid if the current instant is within its
     * validity period.
     *
     * @return {@code true} if the attribute is currently valid, {@code false} otherwise.
     */
    public boolean isValid() {
        Instant now = Instant.now();
        return now.isAfter(this.getValidFrom()) && now.isBefore(this.getValidUntil());
    }

    @Override
    public byte[] getSigningData() {
        byte[] identifierBytes = Bytes.concat(this.identifier.getName().getBytes(), this.identifier.getProvider().getAddress());
        byte[] validFromBytes = Longs.toByteArray(this.getValidFrom().toEpochMilli());
        byte[] validUntilBytes = Longs.toByteArray(this.getValidUntil().toEpochMilli());
        return Bytes.concat(identifierBytes, validFromBytes, validUntilBytes, this.getValueAsBytes());
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        PolicyAttribute<?> that = (PolicyAttribute<?>) object;
        // The value supplier is no part of the identity of an attribute: it states how the publishing AASP obtains
        // the value, so that a transmitted attribute equals the published one it was derived from.
        return Objects.equals(identifier, that.identifier) && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validityDuration, that.validityDuration) && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier, validFrom, validityDuration, value);
    }
}
