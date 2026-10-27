package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.AccessPolicy;
import com.gstuer.casc.pdp.attribute.AttributeSubscriber;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class EvaluationManager {
    private static final long DEFAULT_DECISION_VALIDITY_MILLISECONDS = TimeUnit.SECONDS.toMillis(60);

    private final Set<PolicyEvaluator> policyEvaluators;
    private final AttributeSubscriber attributeSubscriber;

    public EvaluationManager(AttributeSubscriber attributeSubscriber) {
        this.policyEvaluators = new HashSet<>();
        this.attributeSubscriber = attributeSubscriber;
    }

    /**
     * Gets the access decisions of all policies whose flow pattern matches the given access request pattern. The
     * decisions of non-applicable policies are included, as they keep an enforcing PEP from mistaking the absence of
     * an applicable policy for the absence of a decision. The conflicts between the returned decisions are not
     * resolved here, as their resolution depends on the individual data frame and is a task of the enforcing PEP.
     *
     * @param pattern the access request pattern of an access request
     * @return the matching access decisions, or the default access decision if no policy matches the pattern.
     */
    public List<AccessDecision> getDecisions(AccessRequestPattern pattern) {
        List<AccessDecision> matchingDecisions = this.getMatchingDecisions(pattern);

        // If no policy matches the access request pattern, the requesting PEP receives the default access decision.
        if (matchingDecisions.isEmpty()) {
            return List.of(constructDefaultDecision(pattern));
        }
        return matchingDecisions;
    }

    /**
     * Verifies the access decisions of a session initialization that a PEP received from another PDP, by stating per
     * access decision whether this PDP holds the same decision. The decisions are verified individually rather than
     * as a set, as the conflicts between them are resolved by the enforcing PEP for the individual data frame: a
     * verdict on their resolution would reject a session initialization of an agreeing PDP whenever a flow is
     * governed by conflicting decisions, since each submitted decision then states its own action and next hops
     * rather than those of the composite decision.
     *
     * @param decisions the access decisions to be verified
     * @return one verdict per access decision, in the order of the given decisions.
     */
    public List<AccessDecisionVerdict> verifyDecisions(Collection<AccessDecision> decisions) {
        return decisions.stream().map(this::verifyDecision).toList();
    }

    /**
     * Verifies a single access decision against the access decisions of this PDP. A decision is confirmed by an own
     * decision of an equal flow pattern that takes the same action for the same next hops, as the two PDPs then
     * evaluated the same policy for the same flow. A deviating action or next hop indicates a fault, a compromise,
     * or an attribute value that changed between the two evaluations. An own decision of a more general flow pattern
     * does not confirm the decision, as this PDP may hold a more specific decision that denies the flow in question.
     * The default access decision does not contribute either, as a verification compares the policy sets of two PDPs
     * rather than the fallback of a PDP that administers no policy for the flow at all.
     *
     * @param decision the access decision to be verified
     * @return the verdict for the given access decision.
     */
    private AccessDecisionVerdict verifyDecision(AccessDecision decision) {
        Optional<AccessDecision> optionalDecision = this.getMatchingDecisions(decision.getPattern()).stream()
                .filter(ownDecision -> ownDecision.getPattern().equals(decision.getPattern())
                        && ownDecision.getAction() == decision.getAction()
                        && ownDecision.getNextHops().equals(decision.getNextHops()))
                .findFirst();

        // A verdict holds until the earlier of the two access decisions expires, as neither PDP vouches for its
        // decision beyond its own period of validity. A negative verdict holds until the verified decision expires,
        // after which the PEP receives a session initialization that is verified anew.
        Instant validUntil = optionalDecision.map(AccessDecision::getValidUntil)
                .filter(decision.getValidUntil()::isAfter)
                .orElse(decision.getValidUntil());
        return new AccessDecisionVerdict(decision, optionalDecision.isPresent(), validUntil);
    }

    /**
     * Gets the access decisions of all policies whose flow pattern matches the given access request pattern and
     * whose period of validity has not elapsed, in a deterministic order.
     *
     * @param pattern the access request pattern to be matched
     * @return the matching access decisions.
     */
    private List<AccessDecision> getMatchingDecisions(AccessRequestPattern pattern) {
        return this.policyEvaluators.parallelStream()
                .map(PolicyEvaluator::getDecision)
                .filter(decision -> pattern.contains(decision.getPattern()) && decision.isValid())
                .sorted()
                .toList();
    }

    /**
     * Constructs the default access decision for an access request pattern that no policy matches. As the decision
     * denies access, its next hop set is empty. Its derivation does not involve attribute values, so that its
     * validity is not constrained by attribute expiry but by a non-attribute-related maximum time of validity.
     *
     * @param pattern the access request pattern the default decision matches exactly
     * @return the default access decision.
     */
    private static AccessDecision constructDefaultDecision(AccessRequestPattern pattern) {
        return new AccessDecision(pattern, AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusMillis(DEFAULT_DECISION_VALIDITY_MILLISECONDS));
    }

    /**
     * Adds an access control policy to be evaluated by this evaluation manager. Two policies may share an equal flow
     * pattern, as their decisions are conflicting decisions that an enforcing PEP resolves into a composite decision.
     * The coherence of the policy set is a property of the set rather than of an individual policy and its
     * validation is a task of the PASP.
     *
     * @param policy the access control policy to be added
     */
    public void addPolicy(AccessPolicy policy) {
        // TODO Track subscribed attributes for removal of policies & associated attributes not required by other policies
        // Create new policy evaluator and start its periodic evaluation.
        PolicyEvaluator policyEvaluator = new PolicyEvaluator(policy, this.attributeSubscriber);
        policyEvaluator.startPeriodicEvaluation();
        this.policyEvaluators.add(policyEvaluator);
    }
}
