package com.gstuer.casc.common;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.UnavailableAttributeException;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Represents an access control policy created by a policy administration point (PAP). A policy is used by a policy
 * decision point (PEP) to perform a dynamic authorization, i.e., to derive an {@link AccessDecision access decision}
 * for a given set of non-flow-related system {@link PolicyAttribute attributes}.
 */
public class AccessPolicy {
    private static final AccessDecision.Action INAPPLICABLE_ACTION = AccessDecision.Action.NOTAPPLICABLE;
    private static final TemporalAmount DEFAULT_VALIDITY = Duration.ofSeconds(60);

    private final AccessRequestPattern flowPattern;
    private final AccessDecision.Action action;
    private final Set<InetAddress> nextHops;
    private final PolicyPredicate predicate;

    /**
     * Constructs a new {@link AccessPolicy access policy}.
     *
     * @param flowPattern the access request pattern this policy is valid for
     * @param action      the action taken for access requests matching the flow pattern
     * @param nextHops    the addresses of the PEPs to which a matching request has to be forwarded to
     * @param predicate   boolean function constraining any relevant non-flow-related system attributes
     */
    public AccessPolicy(AccessRequestPattern flowPattern, AccessDecision.Action action,
                        Collection<InetAddress> nextHops, PolicyPredicate predicate) {
        this.flowPattern = Objects.requireNonNull(flowPattern);
        this.action = Objects.requireNonNull(action);
        this.nextHops = Objects.isNull(nextHops) ? Set.of() : Set.copyOf(nextHops);
        this.predicate = Objects.requireNonNull(predicate);
    }

    /**
     * Constructs a new {@link AccessPolicy access policy} with a single next hop, which is the common case of a
     * policy permitting exactly one recipient.
     *
     * @param flowPattern the access request pattern this policy is valid for
     * @param action      the action taken for access requests matching the flow pattern
     * @param nextHop     the address of the PEP to which a matching request has to be forwarded to, or {@code null}
     * @param predicate   boolean function constraining any relevant non-flow-related system attributes
     */
    public AccessPolicy(AccessRequestPattern flowPattern, AccessDecision.Action action, InetAddress nextHop,
                        PolicyPredicate predicate) {
        this(flowPattern, action, Objects.isNull(nextHop) ? Set.of() : Set.of(nextHop), predicate);
    }

    /**
     * Derives an {@link AccessDecision access decision} from this {@link AccessPolicy access policy} for a given set of
     * non-flow-related system {@link PolicyAttribute attributes}.
     *
     * If the auxiliary predicates of this policy match the current system state, the policy is applicable to the
     * matching data frame flows, and the derived decision states the action and the next hops of the policy.
     * Otherwise the policy is not applicable, and the derived decision neither grants nor denies the matching flows,
     * so that it does not override an applicable decision. An attribute value that cannot be fetched keeps the
     * auxiliary precondition from matching and therefore yields a decision that is not applicable either.
     *
     * @param attributes a map of non-flow-related system attributes using their identifiers as map keys
     * @return an {@link AccessDecision access decision} derived from this {@link AccessPolicy access policy}.
     */
    public AccessDecision evaluate(Map<AttributeIdentifier, PolicyAttribute<?>> attributes) {
        PolicyPredicate.Evaluation evaluation;
        try {
            // Evaluation was possible for current system state
            evaluation = predicate.evaluate(attributes);
        } catch (UnavailableAttributeException exception) {
            // Evaluation was not possible due to unavailable attribute values
            // -> Should only happen during initial attribute fetching phase.
            return new AccessDecision(flowPattern, INAPPLICABLE_ACTION, Set.of(),
                    Instant.now().plus(DEFAULT_VALIDITY));
        }

        if (evaluation.isPositive()) {
            return new AccessDecision(flowPattern, action, nextHops, evaluation.getEndOfValidity());
        } else {
            return new AccessDecision(flowPattern, INAPPLICABLE_ACTION, Set.of(), evaluation.getEndOfValidity());
        }
    }

    public AccessRequestPattern getFlowPattern() {
        return this.flowPattern;
    }

    public AccessDecision.Action getAction() {
        return this.action;
    }

    public Set<InetAddress> getNextHops() {
        return this.nextHops;
    }

    public PolicyPredicate getPredicate() {
        return this.predicate;
    }
}
