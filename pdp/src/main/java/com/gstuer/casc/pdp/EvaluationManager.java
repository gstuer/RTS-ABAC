package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessPolicy;
import com.gstuer.casc.common.attribute.AttributeSubscriber;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
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
        List<AccessDecision> matchingDecisions = this.policyEvaluators.parallelStream()
                .map(PolicyEvaluator::getDecision)
                .filter(decision -> pattern.contains(decision.getPattern()) && decision.isValid())
                .sorted()
                .toList();

        // If no policy matches the access request pattern, the requesting PEP receives the default access decision.
        if (matchingDecisions.isEmpty()) {
            return List.of(constructDefaultDecision(pattern));
        }
        return matchingDecisions;
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
