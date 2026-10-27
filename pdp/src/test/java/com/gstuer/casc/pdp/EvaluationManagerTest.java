package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.AccessPolicy;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.attribute.AttributeSubscriber;
import com.gstuer.casc.common.attribute.predicate.StaticResultPredicate;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import com.gstuer.casc.common.pattern.IpPattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the derivation of the access decisions a PDP sends in a session initialization. A PDP identifies all
 * applicable policies via flow pattern matching and transmits their decisions, as the conflicts between them are
 * resolved by the enforcing PEP for the individual data frame rather than by the PDP.
 */
public class EvaluationManagerTest {
    private static final Instant VALID_UNTIL = Instant.now().plusSeconds(60);

    private EvaluationManager evaluationManager;
    private AccessRequestPattern ethernetPattern;
    private AccessRequestPattern ipPattern;
    private InetAddress firstNextHop;
    private InetAddress secondNextHop;

    @BeforeEach
    public void setUp() throws Exception {
        BlockingQueue<AccessControlMessage<?>> egress = new LinkedBlockingQueue<>();
        AuthenticationClient authenticationClient = new AuthenticationClient(InetAddress.getByName("127.0.0.1"),
                new NoOperationAuthenticator(), egress);
        this.evaluationManager = new EvaluationManager(new AttributeSubscriber(authenticationClient, egress));

        this.ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        this.ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"),
                InetAddress.getByName("255.255.255.255"), IpNumber.UDP, this.ethernetPattern);
        this.firstNextHop = InetAddress.getByName("127.0.0.10");
        this.secondNextHop = InetAddress.getByName("127.0.0.11");
    }

    /**
     * If no access control policy matches the access request pattern, the PDP answers with the default access
     * decision. It denies access, matches the access request pattern of the access request exactly, and permits no
     * recipient, so that the requesting PEP drops the matching data frames in accordance with the closed access
     * control system.
     */
    @Test
    public void testDefaultDecisionIsDerivedIfNoPolicyMatches() {
        List<AccessDecision> decisions = this.evaluationManager.getDecisions(this.ipPattern);

        assertEquals(1, decisions.size());
        AccessDecision decision = decisions.get(0);
        assertTrue(decision.isDenying());
        assertEquals(this.ipPattern, decision.getPattern(),
                "The default decision matches the access request pattern exactly.");
        assertTrue(decision.getNextHops().isEmpty(), "A denying decision permits no recipient.");
        assertTrue(decision.isValid(), "The default decision has a non-attribute-related time of validity.");
    }

    /**
     * A session initialization contains the decisions of all policies whose flow pattern matches the access request
     * pattern, not only the decision of the most specifically matching policy, as the applicable resolution depends
     * on the individual data frame and is therefore a task of the enforcing PEP.
     */
    @Test
    public void testDecisionsOfAllMatchingPoliciesAreDerived() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ethernetPattern, this.firstNextHop));
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.secondNextHop));

        List<AccessDecision> decisions = this.evaluationManager.getDecisions(this.ipPattern);
        assertEquals(2, decisions.size());
        assertEquals(Set.of(this.ethernetPattern, this.ipPattern),
                decisions.stream().map(AccessDecision::getPattern).collect(Collectors.toSet()));
    }

    /**
     * A policy whose flow pattern does not match the access request pattern contributes no decision, as the pattern
     * matching precedes the policy evaluation.
     */
    @Test
    public void testPolicyOfDeviatingFlowPatternContributesNoDecision() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));

        List<AccessDecision> decisions = this.evaluationManager.getDecisions(this.ethernetPattern);
        assertEquals(1, decisions.size());
        assertTrue(decisions.get(0).isDenying(), "Only the default decision remains for an unmatched pattern.");
    }

    /**
     * Two policies may share an equal flow pattern. Their decisions are conflicting, as neither of them matches a
     * data frame more specifically than the other, and the enforcing PEP resolves them into a composite decision.
     * The PDP therefore transmits both of them instead of rejecting the policy set.
     */
    @Test
    public void testPoliciesOfEqualFlowPatternBothContributeADecision() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.secondNextHop));

        List<AccessDecision> decisions = this.evaluationManager.getDecisions(this.ipPattern);
        assertEquals(2, decisions.size());
        assertEquals(Set.of(Set.of(this.firstNextHop), Set.of(this.secondNextHop)),
                decisions.stream().map(AccessDecision::getNextHops)
                        .collect(Collectors.toSet()));
    }

    /**
     * The decision of a policy that is not applicable in the current system state is transmitted as well. It keeps
     * the enforcing PEP from mistaking the absence of an applicable policy for the absence of a decision, so that
     * the PEP drops the matching data frames instead of repeating the access request for every one of them.
     */
    @Test
    public void testDecisionOfNonApplicablePolicyIsDerived() {
        this.evaluationManager.addPolicy(new AccessPolicy(this.ipPattern, AccessDecision.Action.GRANT,
                Set.of(this.firstNextHop), new StaticResultPredicate(false, Duration.ofSeconds(60))));

        List<AccessDecision> decisions = this.evaluationManager.getDecisions(this.ipPattern);
        assertEquals(1, decisions.size());
        AccessDecision decision = decisions.get(0);
        assertFalse(decision.isApplicable(), "A policy that does not apply yields a non-applicable decision.");
        assertFalse(decision.isDenying(), "A non-applicable decision must not deny, as it would override a grant.");
        assertTrue(decision.getNextHops().isEmpty());
        assertEquals(this.ipPattern, decision.getPattern());
    }

    /**
     * A policy permitting several recipients yields a decision whose next hop set contains all of them, so that the
     * enforcing PEP forwards a granted data frame to each of them.
     */
    @Test
    public void testPolicyWithSeveralNextHopsYieldsAllOfThem() {
        this.evaluationManager.addPolicy(new AccessPolicy(this.ipPattern, AccessDecision.Action.GRANT,
                Set.of(this.firstNextHop, this.secondNextHop),
                new StaticResultPredicate(true, Duration.ofSeconds(60))));

        List<AccessDecision> decisions = this.evaluationManager.getDecisions(this.ipPattern);
        assertEquals(1, decisions.size());
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), decisions.get(0).getNextHops());
    }

    //
    // Server-aided verification: the verdict a PDP states per submitted access decision
    //

    /**
     * A PDP confirms an access decision if it holds the same decision for the same flow pattern, i.e. if the two
     * PDPs derived the same action and the same next hops from the policies they administer for that flow.
     */
    @Test
    public void testIdenticalDecisionIsConfirmed() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));
        AccessDecision decision = grant(this.ipPattern, this.firstNextHop);

        List<AccessDecisionVerdict> verdicts = this.evaluationManager.verifyDecisions(List.of(decision));

        assertEquals(1, verdicts.size(), "One verdict per submitted access decision is returned.");
        assertEquals(decision, verdicts.get(0).getDecision(), "A verdict carries the decision it concerns.");
        assertTrue(verdicts.get(0).isVerified());
    }

    /**
     * A deviating action is not confirmed, as it indicates a fault, a compromise, or an attribute value that changed
     * between the two evaluations.
     */
    @Test
    public void testDeviatingActionIsNotConfirmed() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));

        List<AccessDecisionVerdict> verdicts = this.evaluationManager.verifyDecisions(List.of(
                new AccessDecision(this.ipPattern, AccessDecision.Action.DENY, Set.of(), VALID_UNTIL),
                new AccessDecision(this.ipPattern, AccessDecision.Action.NOTAPPLICABLE, Set.of(), VALID_UNTIL)));

        assertFalse(verdicts.get(0).isVerified());
        assertFalse(verdicts.get(1).isVerified());
    }

    /**
     * A deviating next hop is not confirmed either, as the two PDPs then permit different recipients for the same
     * data frame flow.
     */
    @Test
    public void testDeviatingNextHopIsNotConfirmed() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));

        List<AccessDecisionVerdict> verdicts = this.evaluationManager.verifyDecisions(List.of(
                grant(this.ipPattern, this.secondNextHop)));

        assertFalse(verdicts.get(0).isVerified());
    }

    /**
     * An own policy of a more general flow pattern does not confirm a decision, as this PDP may hold a more specific
     * policy that denies the flow in question. Verifying against an equal flow pattern keeps the verdict sound
     * without the verifying PDP having to reason about the conflict resolution of the enforcing PEP.
     */
    @Test
    public void testDecisionOfMoreSpecificFlowPatternIsNotConfirmed() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ethernetPattern, this.firstNextHop));

        List<AccessDecisionVerdict> verdicts = this.evaluationManager.verifyDecisions(List.of(
                grant(this.ipPattern, this.firstNextHop)));

        assertFalse(verdicts.get(0).isVerified());
    }

    /**
     * A flow pattern that no own policy matches is not confirmed. The default access decision does not contribute to
     * a verification, as a verification compares the policy sets of two PDPs rather than the fallback of a PDP that
     * administers no policy for the flow at all.
     */
    @Test
    public void testDecisionOfUnmatchedFlowPatternIsNotConfirmed() {
        List<AccessDecisionVerdict> verdicts = this.evaluationManager.verifyDecisions(List.of(
                grant(this.ipPattern, this.firstNextHop),
                new AccessDecision(this.ipPattern, AccessDecision.Action.DENY, Set.of(), VALID_UNTIL)));

        assertFalse(verdicts.get(0).isVerified(), "A PDP without a matching policy confirms no grant.");
        assertFalse(verdicts.get(1).isVerified(), "Nor does its default decision confirm a denial.");
    }

    /**
     * Each conflicting decision of a flow is confirmed individually. A verdict on their resolution would reject the
     * session initialization of an agreeing PDP whenever a flow is governed by conflicting decisions, as each
     * submitted decision then states its own next hops rather than those of the composite decision.
     */
    @Test
    public void testConflictingDecisionsAreConfirmedIndividually() {
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.secondNextHop));

        List<AccessDecisionVerdict> verdicts = this.evaluationManager.verifyDecisions(List.of(
                grant(this.ipPattern, this.firstNextHop),
                grant(this.ipPattern, this.secondNextHop)));

        assertTrue(verdicts.get(0).isVerified());
        assertTrue(verdicts.get(1).isVerified());
    }

    /**
     * A verdict holds until the earlier of the two access decisions expires, as neither PDP vouches for its decision
     * beyond its own period of validity. A negative verdict holds until the verified decision expires, after which
     * the enforcing PEP requests a session initialization that is verified anew.
     */
    @Test
    public void testVerdictExpiresWithTheEarlierOfTheTwoDecisions() {
        // The decisions of this policy are valid for 60 seconds, i.e. longer than the submitted decision below.
        this.evaluationManager.addPolicy(grantingPolicy(this.ipPattern, this.firstNextHop));
        AccessDecision shortLived = new AccessDecision(this.ipPattern, AccessDecision.Action.GRANT,
                Set.of(this.firstNextHop), Instant.now().plusSeconds(5));
        AccessDecision longLived = new AccessDecision(this.ipPattern, AccessDecision.Action.GRANT,
                Set.of(this.firstNextHop), Instant.now().plusSeconds(600));
        AccessDecision rejected = new AccessDecision(this.ipPattern, AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(5));

        List<AccessDecisionVerdict> verdicts = this.evaluationManager
                .verifyDecisions(List.of(shortLived, longLived, rejected));

        assertEquals(shortLived.getValidUntil(), verdicts.get(0).getValidUntil(),
                "The submitted decision expires first, so that the verdict expires with it.");
        assertTrue(verdicts.get(1).getValidUntil().isBefore(longLived.getValidUntil()),
                "The own decision expires first, so that the verdict expires with it.");
        assertEquals(rejected.getValidUntil(), verdicts.get(2).getValidUntil(),
                "A negative verdict holds until the verified decision expires.");
    }

    private static AccessDecision grant(AccessRequestPattern pattern, InetAddress nextHop) {
        return new AccessDecision(pattern, AccessDecision.Action.GRANT, Set.of(nextHop), VALID_UNTIL);
    }

    private static AccessPolicy grantingPolicy(AccessRequestPattern pattern, InetAddress nextHop) {
        return new AccessPolicy(pattern, AccessDecision.Action.GRANT, Set.of(nextHop),
                new StaticResultPredicate(true, Duration.ofSeconds(60)));
    }
}
