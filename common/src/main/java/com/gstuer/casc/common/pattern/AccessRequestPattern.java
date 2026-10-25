package com.gstuer.casc.common.pattern;

import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.util.Objects;

/**
 * A pattern that represents an access request in a network. The access request pattern is either used as a rule for
 * matching network traffic or it represents a specific packet of the network traffic that has to satisfy the network rules.
 * Note: This class has a natural ordering that is inconsistent with equals.
 */
public abstract class AccessRequestPattern implements Signable, Comparable<AccessRequestPattern> {
    public final AccessRequestPattern enclosedPattern;

    protected AccessRequestPattern(AccessRequestPattern enclosedPattern) {
        this.enclosedPattern = enclosedPattern;
    }

    /**
     * Checks if this pattern contains the given pattern. A pattern {@code a} contains another pattern {@code b}, iff
     * {@code b} &#8838; {@code a}. In other words, if a pattern and its enclosed patterns are part of this pattern, then the
     * former pattern is contained in the latter one (this). The other pattern is tested as an atomic piece, i.e. it
     * is not contained if it and its enclosed patterns are only contained individually but not as a whole. Consequently,
     * the following equation holds: a.contains(b) &#8800; &#8704; c &#8712; b: a.contains(c).
     *
     * @param pattern the pattern that is or is not contained in this
     * @return {@code true} if this pattern contains the given pattern, {@code false} otherwise.
     */
    public boolean contains(AccessRequestPattern pattern) {
        return this.contains(pattern, true);
    }

    /**
     * Checks if this pattern contains the given pattern. A pattern {@code a} contains another pattern {@code b}, iff
     * {@code b} &#8838; {@code a}. In other words, if a pattern and its enclosed patterns are part of this pattern, then the
     * former pattern is contained in the latter one (this). The other pattern is tested as an atomic piece, i.e. it
     * is not contained if it and its enclosed patterns are only contained individually but not as a whole. Consequently,
     * the following equation holds: a.contains(b) &#8800; &#8704; c &#8712; b: a.contains(c).
     *
     * @param pattern   the pattern that is or is not contained in this
     * @param allowGaps signals if matching is continued with the enclosed pattern of this, if this is not equal to the
     *                  given pattern
     * @return {@code true} if this pattern contains the given pattern, {@code false} otherwise.
     */
    public boolean contains(AccessRequestPattern pattern, boolean allowGaps) {
        // Test if the two patterns are equal without their enclosed patterns
        if (this.equalsIsolated(pattern)) {
            // If the other pattern has an enclosed pattern it must be equal to this.enclosedPattern
            // To allow unequal gaps in patterns, set allowGaps to true for sub-pattern matching
            // Note: The empty pattern is contained in every pattern!
            boolean sameEnclosedPattern = !pattern.hasEnclosedPattern() || (this.hasEnclosedPattern()
                    && this.enclosedPattern.contains(pattern.getEnclosedPattern(), false));
            if (sameEnclosedPattern) {
                return true;
            }
        }

        // Test if the two patterns or their enclosed patterns are unequal, continue search in subtree
        if (allowGaps && this.hasEnclosedPattern()) {
            return this.enclosedPattern.contains(pattern, true);
        }

        // Most generic contains matcher must always return false to make all patterns "comparable"
        return false;
    }

    /**
     * Gets the enclosed pattern.
     *
     * @return the enclosed pattern if available, {@code null} otherwise.
     */
    public AccessRequestPattern getEnclosedPattern() {
        return enclosedPattern;
    }

    /**
     * Signals whether this pattern has an enclosed pattern.
     *
     * @return {@code true} if this pattern has an enclosed pattern, {@code false} otherwise.
     */
    public boolean hasEnclosedPattern() {
        return Objects.nonNull(enclosedPattern);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        AccessRequestPattern that = (AccessRequestPattern) object;
        return Objects.equals(this.enclosedPattern, that.enclosedPattern);
    }

    /**
     * Checks if two patterns are equal, ignoring their enclosed patterns.
     * Apart from this, behaves as specified by {@link #equals(Object)}.
     *
     * @param object the object with which to compare.
     * @return {@code true} if this pattern is equal to the given object apart from enclosed patterns,
     * {@code false} otherwise.
     */
    public abstract boolean equalsIsolated(Object object);

    @Override
    public int hashCode() {
        return Objects.hashCode(enclosedPattern);
    }

    @Override
    public String toString() {
        try {
            return new JsonProcessor(true).convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    public byte[] getSigningData() {
        // A pattern without an enclosed pattern contributes no further signing data, as it constrains no further
        // protocol layer. Such a pattern is a valid flow pattern, e.g. one constraining an IP layer without
        // constraining the link layer beneath it.
        return this.hasEnclosedPattern() ? this.enclosedPattern.getSigningData() : new byte[0];
    }

    @Override
    public int compareTo(AccessRequestPattern that) {
        if (this.contains(that) && that.contains(this)) {
            // Equal patterns
            return 0;
        } else if (this.contains(that)) {
            return -1;
        } else if (that.contains(this)) {
            return 1;
        }
        // Unequal pattern without relation
        return 0;
    }
}
