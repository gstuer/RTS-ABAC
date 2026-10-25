package com.gstuer.casc.common;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.net.InetAddress;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Represents an access decision taken by a policy decision point (PDP) and enforced by a policy enforcement point (PEP).
 */
public class AccessDecision implements Signable, Comparable<AccessDecision> {
    private final AccessRequestPattern pattern;
    private final Action action;
    private final Set<InetAddress> nextHops;
    private final Instant validUntil;

    /**
     * Constructs a new {@link AccessDecision access decision}.
     *
     * @param pattern    the access request pattern this decision is valid for
     * @param action     the action taken for the access request pattern
     * @param nextHops   the addresses of the PEPs to which a matching frame should be forwarded to
     * @param validUntil the point in time until the taken decision is valid
     */
    public AccessDecision(AccessRequestPattern pattern, Action action, Collection<InetAddress> nextHops,
                          Instant validUntil) {
        this.pattern = Objects.requireNonNull(pattern);
        this.action = Objects.requireNonNull(action);
        this.nextHops = Objects.isNull(nextHops) ? Set.of() : Set.copyOf(nextHops);
        this.validUntil = Objects.requireNonNull(validUntil);
    }

    /**
     * Constructs a new {@link AccessDecision access decision} with a single next hop, which is the common case of a
     * policy permitting exactly one recipient.
     *
     * @param pattern    the access request pattern this decision is valid for
     * @param action     the action taken for the access request pattern
     * @param nextHop    the address of the PEP to which a matching frame should be forwarded to, or {@code null}
     * @param validUntil the point in time until the taken decision is valid
     */
    public AccessDecision(AccessRequestPattern pattern, Action action, InetAddress nextHop, Instant validUntil) {
        this(pattern, action, Objects.isNull(nextHop) ? Set.of() : Set.of(nextHop), validUntil);
    }

    /**
     * Gets the {@link AccessRequestPattern access request pattern} this decision is valid for.
     *
     * @return the access request pattern.
     */
    public AccessRequestPattern getPattern() {
        return pattern;
    }

    /**
     * Gets the {@link Action action} to be taken for matching {@link AccessRequestPattern patterns}.
     *
     * @return the action.
     */
    public Action getAction() {
        return action;
    }

    /**
     * Checks whether this access decision is granting matching {@link AccessRequestPattern patterns}.
     *
     * @return {@code true} if decision grants a matching pattern, {@code false} otherwise.
     */
    public boolean isGranting() {
        return this.action.equals(Action.GRANT);
    }

    /**
     * Checks whether this access decision is denying matching {@link AccessRequestPattern patterns}.
     *
     * @return {@code true} if decision denies a matching pattern, {@code false} otherwise.
     */
    public boolean isDenying() {
        return this.action.equals(Action.DENY);
    }

    /**
     * Checks whether the policy this access decision was derived from is applicable in the system state it was derived
     * for. A decision that is not applicable neither grants nor denies the matching data frames, so that it must
     * neither override an applicable decision nor contribute to a composite decision.
     *
     * @return {@code true} if the underlying policy is applicable, {@code false} otherwise.
     */
    public boolean isApplicable() {
        return !this.action.equals(Action.NOTAPPLICABLE);
    }

    /**
     * Gets the addresses of the PEPs to which a matching frame should be forwarded to. The set is non-empty only for a
     * granting access decision, as a denied data frame is dropped rather than forwarded.
     *
     * @return the set of next hop addresses.
     */
    public Set<InetAddress> getNextHops() {
        return this.nextHops;
    }

    /**
     * Checks whether the PEP at the given address is permitted to receive the data frames of this access decision.
     *
     * @param address the address of the PEP in question
     * @return {@code true} if the given address is a next hop of this decision, {@code false} otherwise.
     */
    public boolean isNextHop(InetAddress address) {
        return this.nextHops.contains(address);
    }

    /**
     * Gets the point in time until the taken decision is valid.
     *
     * @return the instant until the decision is valid.
     */
    public Instant getValidUntil() {
        return validUntil;
    }

    /**
     * Checks whether this access decision is currently valid. An access decision is valid if the current instant is
     * within its validity period, i.e. before its expiration as indicated by {@link #getValidUntil()}.
     *
     * @return {@code true} if the decision is currently valid, {@code false} otherwise.
     */
    public boolean isValid() {
        return Instant.now().isBefore(this.validUntil);
    }

    /**
     * Checks whether this access decision is valid at a specified time in the future. An access decision is valid if
     * the current instant is within its validity period, i.e. before its expiration as indicated by
     * {@link #getValidUntil()}.
     *
     * @param temporalOffset the offset from {@link Instant#now()} specifying the time for which the validity is checked
     * @return {@code true} if the decision is valid at the specified time, {@code false} otherwise.
     */
    public boolean isValid(TemporalAmount temporalOffset) {
        return Instant.now().plus(temporalOffset).isBefore(this.validUntil);
    }

    /**
     * Checks whether this access decision is valid at a specified point in time.
     *
     * @param instant the point in time for which the validity is checked
     * @return {@code true} if the decision is valid at the given instant, {@code false} otherwise.
     */
    public boolean isValidAt(Instant instant) {
        return instant.isBefore(this.validUntil);
    }

    @Override
    public byte[] getSigningData() {
        byte[] patternBytes = this.pattern.getSigningData();
        byte[] decisionBytes = Ints.toByteArray(this.action.ordinal());

        // The next hops are signed in a deterministic order, as the set of next hops itself is unordered.
        List<InetAddress> sortedNextHops = this.nextHops.stream()
                .sorted(Comparator.comparing(InetAddress::getHostAddress)).toList();
        byte[] nextHopBytes = new byte[0];
        for (InetAddress nextHop : sortedNextHops) {
            nextHopBytes = Bytes.concat(nextHopBytes, nextHop.getAddress());
        }

        byte[] validUntilBytes = Longs.toByteArray(this.validUntil.toEpochMilli());
        return Bytes.concat(patternBytes, decisionBytes, nextHopBytes, validUntilBytes);
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
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        AccessDecision that = (AccessDecision) object;
        return Objects.equals(pattern, that.pattern)
                && action == that.action && Objects.equals(nextHops, that.nextHops)
                && Objects.equals(validUntil, that.validUntil);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pattern, action, nextHops, validUntil);
    }

    /**
     * Compares this access decision to another one. The ordering groups the decisions of related flow patterns and is
     * total enough to keep unequal decisions distinguishable within a sorted set. It does not express the precedence
     * of one decision over another, which the conflict resolution of a PEP determines rather than an ordering.
     * Note: This class has a natural ordering that is inconsistent with equals, as the ordering of flow patterns is.
     *
     * @param that the access decision to be compared to this one
     * @return a negative integer, zero, or a positive integer as this decision is less than, equal to, or greater
     * than the given access decision.
     */
    @Override
    public int compareTo(AccessDecision that) {
        int patternComparison = this.getPattern().compareTo(that.getPattern());
        if (patternComparison != 0) {
            // Related but unequal patterns
            return patternComparison;
        }
        // Equal or unrelated patterns: Deny > Grant
        if (this.isGranting() && that.isDenying()) {
            return 1;
        } else if (this.isDenying() && that.isGranting()) {
            return -1;
        }
        // Same pattern, same action -> Fall back on hash values.
        return Integer.compare(this.hashCode(), that.hashCode());
    }

    /**
     * Represents the action of an {@link AccessDecision access decision}, which must be taken for matching
     * {@link AccessRequestPattern patterns} at a policy enforcement point (PEP).
     */
    public enum Action {
        /**
         * An access request must be granted.
         */
        GRANT,
        /**
         * An access request must be denied.
         */
        DENY,
        /**
         * The policy the decision was derived from is not applicable in the system state it was derived for, so that
         * the decision neither grants nor denies a matching access request.
         */
        NOTAPPLICABLE;
    }
}
