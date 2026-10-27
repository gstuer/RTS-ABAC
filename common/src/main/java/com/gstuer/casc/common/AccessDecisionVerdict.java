package com.gstuer.casc.common;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents the outcome of the server-aided verification of a single {@link AccessDecision access decision}, i.e. the
 * statement of a verifying policy decision point (PDP) whether it holds the same access decision for the flow pattern
 * of the decision in question.
 * <p>
 * A verdict is valid for a period of time, so that a policy enforcement point (PEP) can retain it instead of
 * verifying the same access decision again for every session initialization it receives. Retaining a negative verdict
 * is what keeps the outcome of a verification undisclosed: without it, a PEP would request an access decision for
 * every data frame of an unverifiable flow and thereby reveal the outcome to the issuing PDP.
 */
public class AccessDecisionVerdict implements Signable {
    private final AccessDecision decision;
    private final boolean verified;
    private final Instant validUntil;

    /**
     * Constructs a new {@link AccessDecisionVerdict access decision verdict}.
     *
     * @param decision   the access decision this verdict concerns, which the verdict carries so that a PEP can
     *                   assign it to a decision of its session initialization independently of the transmission order
     * @param verified   whether the verifying PDP holds the given access decision as well
     * @param validUntil the point in time until the verdict holds
     */
    public AccessDecisionVerdict(AccessDecision decision, boolean verified, Instant validUntil) {
        this.decision = Objects.requireNonNull(decision);
        this.verified = verified;
        this.validUntil = Objects.requireNonNull(validUntil);
    }

    /**
     * Gets the {@link AccessDecision access decision} this verdict concerns.
     *
     * @return the access decision.
     */
    public AccessDecision getDecision() {
        return this.decision;
    }

    /**
     * Checks whether the verifying PDP confirmed the access decision of this verdict.
     *
     * @return {@code true} if the decision is confirmed, {@code false} otherwise.
     */
    public boolean isVerified() {
        return this.verified;
    }

    /**
     * Gets the point in time until this verdict holds. It is bounded by the periods of validity of the verified
     * access decision and of the access decision the verifying PDP compared it to, as neither PDP vouches for its
     * decision beyond its expiry.
     *
     * @return the instant until the verdict is valid.
     */
    public Instant getValidUntil() {
        return this.validUntil;
    }

    /**
     * Checks whether this verdict is currently valid, i.e. whether it may be retained instead of being requested
     * again.
     *
     * @return {@code true} if the verdict is currently valid, {@code false} otherwise.
     */
    public boolean isValid() {
        return Instant.now().isBefore(this.validUntil);
    }

    @Override
    public byte[] getSigningData() {
        return Bytes.concat(this.decision.getSigningData(), new byte[]{(byte) (this.verified ? 1 : 0)},
                Longs.toByteArray(this.validUntil.toEpochMilli()));
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
        AccessDecisionVerdict that = (AccessDecisionVerdict) object;
        return this.verified == that.verified && Objects.equals(this.decision, that.decision)
                && Objects.equals(this.validUntil, that.validUntil);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.decision, this.verified, this.validUntil);
    }
}
