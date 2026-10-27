package com.gstuer.casc.common;

import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the {@link AccessDecision access decisions} available at a policy enforcement point (PEP) into the single
 * decision to be enforced for a data frame. The resolution implements the decision enforcement function and the
 * two-step conflict resolution of the RTS-ABAC approach:
 * <ol>
 *     <li>The decisions whose flow pattern matches the frame, whose period of validity includes the point in time of
 *     the enforcement, and whose underlying policy is applicable are selected, as only those contribute to the
 *     enforcement. The decisions of non-applicable policies are discarded beforehand, so that such a policy can
 *     neither override a more general policy nor contribute to a composite decision.</li>
 *     <li>The decision with the most specifically matching flow pattern is selected, where a flow pattern matches
 *     more specifically than another one if its set of frame predicates is a strict superset of the other one.</li>
 *     <li>If no unique decision results, the maximally specific decisions are conflicting and are combined into a
 *     composite decision, which grants the frame only if all of them grant it, permits the union of their next hops,
 *     and expires as soon as the first of them expires.</li>
 * </ol>
 * The resolution yields the action, the next hops, and the period of validity of the composite decision rather than a
 * complete {@link AccessDecision}: the union of the conflicting flow patterns is required to represent a composite
 * decision as a decision in its own right, whereas the enforcement of a data frame consumes its action and its next
 * hops only, and the composite decision is never transmitted. A {@link DecisionCache decision cache} memoises the
 * resolution of a flow for the period of validity it inherits, so that the composite decision of a flow is derived
 * once rather than once per data frame.
 */
public final class DecisionResolver {
    private DecisionResolver() {
        throw new AssertionError("No instances of this utility class allowed.");
    }

    /**
     * Resolves the access decisions available at a PEP into the decision to be enforced for a data frame.
     *
     * @param decisions      the access decisions available at the PEP
     * @param requestPattern the access request pattern of the data frame to be enforced
     * @param instant        the point in time of the enforcement
     * @return the resolution to be enforced, or an empty optional if the PEP holds no valid access decision whose
     * flow pattern matches the data frame and therefore has to request one.
     */
    public static Optional<DecisionResolution> getResolution(Collection<AccessDecision> decisions,
                                                             AccessRequestPattern requestPattern, Instant instant) {
        Objects.requireNonNull(requestPattern);
        Objects.requireNonNull(instant);

        // Decisions whose flow pattern matches the frame and whose period of validity includes the given instant
        List<AccessDecision> matchingDecisions = decisions.stream()
                .filter(decision -> requestPattern.contains(decision.getPattern()) && decision.isValidAt(instant))
                .toList();
        if (matchingDecisions.isEmpty()) {
            // The PEP holds no current access decision for the frame and has to request one.
            return Optional.empty();
        }

        // The decisions of non-applicable policies do not contribute to the enforcement. If none remains, no policy
        // applies to the frame, which a PEP distinguishes from the absence of a decision: the frame is dropped in
        // accordance with the closed access control system instead of triggering an access request.
        List<AccessDecision> applicableDecisions = matchingDecisions.stream()
                .filter(AccessDecision::isApplicable).toList();
        if (applicableDecisions.isEmpty()) {
            return Optional.of(new DecisionResolution(AccessDecision.Action.NOTAPPLICABLE, Set.of(),
                    getEarliestExpiry(matchingDecisions)));
        }

        // Step 1: Select the decision of the most specifically matching flow pattern.
        List<AccessDecision> specificDecisions = getMaximallySpecificDecisions(applicableDecisions);
        if (specificDecisions.size() == 1) {
            AccessDecision decision = specificDecisions.get(0);
            return Optional.of(new DecisionResolution(decision.getAction(), decision.getNextHops(),
                    decision.getValidUntil()));
        }

        // Step 2: Combine the conflicting maximally specific decisions into a composite decision.
        return Optional.of(constructCompositeResolution(specificDecisions));
    }

    /**
     * Gets the maximally specific access decisions of a set of matching access decisions, i.e. those for which no
     * other matching decision has a more specific flow pattern. Two or more maximally specific decisions are
     * conflicting, as neither of them matches more specifically than the other.
     *
     * @param decisions the matching access decisions
     * @return the maximally specific access decisions.
     */
    public static List<AccessDecision> getMaximallySpecificDecisions(Collection<AccessDecision> decisions) {
        return decisions.stream()
                .filter(decision -> decisions.stream()
                        .noneMatch(other -> isMoreSpecific(other.getPattern(), decision.getPattern())))
                .toList();
    }

    /**
     * Constructs the composite decision of two or more conflicting access decisions. The composite decision grants a
     * data frame only if all conflicting decisions grant it, i.e. a denying access decision takes precedence over a
     * granting one. It permits the union of the next hops of the conflicting decisions, as each granting decision
     * independently permits its recipients, and it expires as soon as the first of the conflicting decisions expires.
     *
     * @param decisions the conflicting access decisions
     * @return the resolution of the composite decision.
     */
    public static DecisionResolution constructCompositeResolution(Collection<AccessDecision> decisions) {
        if (decisions.isEmpty()) {
            throw new IllegalArgumentException("A composite decision requires at least one access decision.");
        }

        Instant validUntil = getEarliestExpiry(decisions);
        if (!decisions.stream().allMatch(AccessDecision::isGranting)) {
            return new DecisionResolution(AccessDecision.Action.DENY, Set.of(), validUntil);
        }
        Set<InetAddress> nextHops = decisions.stream()
                .flatMap(decision -> decision.getNextHops().stream())
                .collect(Collectors.toUnmodifiableSet());
        return new DecisionResolution(AccessDecision.Action.GRANT, nextHops, validUntil);
    }

    /**
     * Checks whether a flow pattern matches a data frame more specifically than another one, i.e. whether its set of
     * frame predicates is a strict superset of the set of frame predicates of the other pattern. As a flow pattern is
     * a set of predicates that all have to match, a superset of predicates constrains the matching data frames
     * further, which is why a more specific policy takes precedence over a more general one.
     *
     * @param pattern      the flow pattern in question
     * @param otherPattern the flow pattern it is compared to
     * @return {@code true} if the given pattern is more specific than the other one, {@code false} otherwise.
     */
    public static boolean isMoreSpecific(AccessRequestPattern pattern, AccessRequestPattern otherPattern) {
        return pattern.contains(otherPattern) && !otherPattern.contains(pattern);
    }

    private static Instant getEarliestExpiry(Collection<AccessDecision> decisions) {
        return decisions.stream().map(AccessDecision::getValidUntil)
                .min(Comparator.naturalOrder())
                .orElseThrow(() -> new IllegalArgumentException("No access decision given."));
    }

    /**
     * Represents the outcome of the conflict resolution at a policy enforcement point (PEP) for a single data frame.
     * It corresponds to the action and the next hops returned by the decision enforcement function, extended by the
     * period of validity that a composite decision inherits from the decisions it replaces.
     *
     * @param action     the action to be taken for the data frame, where {@code NOTAPPLICABLE} indicates that the PEP
     *                   holds a matching and valid access decision but that no policy applies to the data frame
     * @param nextHops   the PEPs permitted to receive the data frame, which is empty unless the action is a grant
     * @param validUntil the point in time until the resolution holds, i.e. the earliest expiry of the decisions it
     *                   was derived from
     */
    public record DecisionResolution(AccessDecision.Action action, Set<InetAddress> nextHops, Instant validUntil) {
        public DecisionResolution {
            Objects.requireNonNull(action);
            Objects.requireNonNull(validUntil);
            nextHops = Objects.isNull(nextHops) ? Set.of() : Set.copyOf(nextHops);
        }

        /**
         * Checks whether the resolution grants the data frame it was derived for.
         *
         * @return {@code true} if the data frame is granted, {@code false} otherwise.
         */
        public boolean isGranting() {
            return this.action.equals(AccessDecision.Action.GRANT);
        }

        /**
         * Checks whether the PEP at the given address is permitted to receive the data frame this resolution was
         * derived for.
         *
         * @param address the address of the PEP in question
         * @return {@code true} if the given address is a next hop of this resolution, {@code false} otherwise.
         */
        public boolean isNextHop(InetAddress address) {
            return this.nextHops.contains(address);
        }
    }
}
