package com.gstuer.casc.common;

import com.gstuer.casc.common.DecisionResolver.DecisionResolution;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import com.gstuer.casc.common.pattern.IpPattern;
import com.gstuer.casc.common.pattern.UdpPattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the decision enforcement function and the two-step conflict resolution of the RTS-ABAC approach.
 * <p>
 * The flow patterns used throughout the tests form the following specificity order, where an arrow points from the
 * more specific to the more general pattern. All four patterns match the data frame whose access request pattern is
 * the UDP pattern, and the isolated IP pattern and the Ethernet pattern are incomparable, i.e. neither of them
 * matches a data frame more specifically than the other.
 * <pre>
 *     UDP -> IP -> ETH
 *             \--> IP(isolated)
 * </pre>
 */
public class DecisionResolverTest {
    private AccessRequestPattern ethernetPattern;
    private AccessRequestPattern ipPattern;
    private AccessRequestPattern isolatedIpPattern;
    private AccessRequestPattern udpPattern;
    private InetAddress firstNextHop;
    private InetAddress secondNextHop;
    private Instant now;

    @BeforeEach
    public void setUp() throws Exception {
        this.ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        this.ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"),
                InetAddress.getByName("255.255.255.255"), IpNumber.UDP, this.ethernetPattern);
        this.isolatedIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"),
                InetAddress.getByName("255.255.255.255"), IpNumber.UDP);
        this.udpPattern = new UdpPattern(10000, 10001, this.ipPattern);
        this.firstNextHop = InetAddress.getByName("127.0.0.10");
        this.secondNextHop = InetAddress.getByName("127.0.0.11");
        this.now = Instant.now();
    }

    //
    // Specificity of flow patterns
    //

    /**
     * A flow pattern matches a data frame more specifically than another one if its set of frame predicates is a
     * strict superset of the predicates of the other pattern. The UDP pattern adds the predicates of a UDP layer to
     * the predicates of the IP pattern and is therefore the more specific one of the two.
     */
    @Test
    public void testPatternWithAdditionalPredicatesIsMoreSpecific() {
        assertTrue(DecisionResolver.isMoreSpecific(this.udpPattern, this.ipPattern));
        assertTrue(DecisionResolver.isMoreSpecific(this.ipPattern, this.ethernetPattern));
        assertFalse(DecisionResolver.isMoreSpecific(this.ipPattern, this.udpPattern));
        assertFalse(DecisionResolver.isMoreSpecific(this.ethernetPattern, this.ipPattern));
    }

    /**
     * Two equal flow patterns constrain the matching data frames equally, so that neither of them matches a data
     * frame more specifically than the other. The corresponding decisions are therefore conflicting.
     */
    @Test
    public void testEqualPatternsAreNotMoreSpecificThanEachOther() {
        assertFalse(DecisionResolver.isMoreSpecific(this.udpPattern, this.udpPattern));
    }

    /**
     * Two flow patterns whose predicates are not in a subset relation match a data frame without one of them
     * matching it more specifically, even though both of them match the same data frame. The isolated IP pattern
     * constrains the IP layer without constraining the Ethernet layer, whereas the Ethernet pattern does the
     * opposite.
     */
    @Test
    public void testIncomparablePatternsAreNotMoreSpecificThanEachOther() {
        assertTrue(this.udpPattern.contains(this.isolatedIpPattern), "Both patterns must match the data frame.");
        assertTrue(this.udpPattern.contains(this.ethernetPattern), "Both patterns must match the data frame.");
        assertFalse(DecisionResolver.isMoreSpecific(this.isolatedIpPattern, this.ethernetPattern));
        assertFalse(DecisionResolver.isMoreSpecific(this.ethernetPattern, this.isolatedIpPattern));
    }

    //
    // Decision enforcement function: the decisions contributing to the enforcement
    //

    /**
     * A decision whose flow pattern does not match the data frame does not contribute to the enforcement. As no other
     * decision matches either, the PEP holds no decision for the data frame and has to request one.
     */
    @Test
    public void testDecisionOfDeviatingFlowPatternIsNotEnforced() {
        AccessDecision decision = grant(this.udpPattern, this.firstNextHop, 60);
        assertTrue(resolve(List.of(decision), this.ethernetPattern).isEmpty());
    }

    /**
     * A decision whose period of validity has elapsed does not contribute to the enforcement, so that the PEP
     * requests a new decision rather than enforcing the expired one.
     */
    @Test
    public void testExpiredDecisionIsNotEnforced() {
        AccessDecision decision = grant(this.udpPattern, this.firstNextHop, -1);
        assertTrue(resolve(List.of(decision), this.udpPattern).isEmpty());
    }

    /**
     * A decision is enforced only up to its expiry, which the resolution evaluates for the point in time passed to
     * it rather than for the current one. A PEP uses this to renew a decision before the data frames of its flow are
     * dropped.
     */
    @Test
    public void testDecisionIsNotEnforcedBeyondTheGivenInstant() {
        AccessDecision decision = grant(this.udpPattern, this.firstNextHop, 60);
        assertTrue(DecisionResolver.getResolution(List.of(decision), this.udpPattern,
                this.now.plusSeconds(30)).isPresent());
        assertTrue(DecisionResolver.getResolution(List.of(decision), this.udpPattern,
                this.now.plusSeconds(90)).isEmpty());
    }

    /**
     * An empty set of decisions leaves the PEP without a decision for the data frame, so that it has to request one.
     */
    @Test
    public void testAbsenceOfDecisionsRequiresAnAccessRequest() {
        assertTrue(resolve(List.of(), this.udpPattern).isEmpty());
    }

    //
    // Decisions of non-applicable policies
    //

    /**
     * The decision of a non-applicable policy neither grants nor denies a data frame. If it is the only matching
     * decision, no policy applies to the data frame, which the PEP distinguishes from the absence of a decision: the
     * data frame is dropped in accordance with the closed access control system instead of triggering a new access
     * request, which the resolution signals by a present resolution that does not grant.
     */
    @Test
    public void testNonApplicableDecisionDropsTheFrameWithoutAnAccessRequest() {
        AccessDecision decision = notApplicable(this.udpPattern, 60);

        Optional<DecisionResolution> resolution = resolve(List.of(decision), this.udpPattern);
        assertTrue(resolution.isPresent(), "A matching decision must not trigger a new access request.");
        assertEquals(AccessDecision.Action.NOTAPPLICABLE, resolution.get().action());
        assertFalse(resolution.get().isGranting());
        assertTrue(resolution.get().nextHops().isEmpty());
    }

    /**
     * A policy that is not applicable must not override a policy that is applicable, even if the two share an equal
     * flow-specifying pattern. The granting decision of the applicable policy is therefore enforced.
     */
    @Test
    public void testNonApplicableDecisionDoesNotOverrideAnApplicableOneOfAnEqualPattern() {
        AccessDecision applicable = grant(this.udpPattern, this.firstNextHop, 60);
        AccessDecision nonApplicable = notApplicable(this.udpPattern, 60);

        DecisionResolution resolution = resolve(List.of(nonApplicable, applicable), this.udpPattern).orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop), resolution.nextHops());
    }

    /**
     * A decision that is not applicable must neither contribute to a composite decision. Although a composite
     * decision denies a data frame as soon as one conflicting decision denies it, a non-applicable decision is
     * discarded beforehand, so that the two granting decisions remain and the composite decision grants the frame.
     */
    @Test
    public void testNonApplicableDecisionDoesNotContributeToACompositeDecision() {
        AccessDecision firstGrant = grant(this.isolatedIpPattern, this.firstNextHop, 60);
        AccessDecision secondGrant = grant(this.ethernetPattern, this.secondNextHop, 60);
        AccessDecision nonApplicable = notApplicable(this.udpPattern, 60);

        DecisionResolution resolution = resolve(List.of(firstGrant, secondGrant, nonApplicable), this.udpPattern)
                .orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), resolution.nextHops());
    }

    /**
     * A non-applicable decision that is more specific than an applicable one must not suppress the applicable
     * decision, as it is discarded before the most specific decision is selected.
     */
    @Test
    public void testNonApplicableDecisionDoesNotSuppressAMoreGeneralApplicableOne() {
        AccessDecision specific = notApplicable(this.udpPattern, 60);
        AccessDecision general = grant(this.ethernetPattern, this.firstNextHop, 60);

        DecisionResolution resolution = resolve(List.of(specific, general), this.udpPattern).orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop), resolution.nextHops());
    }

    //
    // Step 1: The most specifically matching decision
    //

    /**
     * A more specific policy takes precedence over a more general one, as a superset of frame predicates constrains
     * the matching data frames further. A specific denial therefore excludes a subset of a flow that a more general
     * policy grants, which is the purpose of a denying policy in the closed access control system of RTS-ABAC.
     */
    @Test
    public void testMoreSpecificDenialExcludesASubsetOfAGrantedFlow() {
        AccessDecision generalGrant = grant(this.ethernetPattern, this.firstNextHop, 60);
        AccessDecision specificDenial = deny(this.udpPattern, 60);

        DecisionResolution resolution = resolve(List.of(generalGrant, specificDenial), this.udpPattern).orElseThrow();
        assertFalse(resolution.isGranting());
        assertTrue(resolution.nextHops().isEmpty(), "A denied data frame is dropped rather than forwarded.");
    }

    /**
     * The precedence of the more specific decision holds in either direction, i.e. a specific grant is enforced
     * although a more general decision denies the flow.
     */
    @Test
    public void testMoreSpecificGrantOverridesAMoreGeneralDenial() {
        AccessDecision generalDenial = deny(this.ethernetPattern, 60);
        AccessDecision specificGrant = grant(this.udpPattern, this.firstNextHop, 60);

        DecisionResolution resolution = resolve(List.of(generalDenial, specificGrant), this.udpPattern).orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop), resolution.nextHops());
    }

    /**
     * The selection of the most specific decision is transitive, i.e. the most specific of three decisions in a
     * specificity chain is enforced and the two more general ones are discarded.
     */
    @Test
    public void testMostSpecificDecisionOfAChainIsEnforced() {
        AccessDecision ethernetDenial = deny(this.ethernetPattern, 60);
        AccessDecision ipDenial = deny(this.ipPattern, 60);
        AccessDecision udpGrant = grant(this.udpPattern, this.firstNextHop, 60);

        DecisionResolution resolution = resolve(List.of(ethernetDenial, ipDenial, udpGrant), this.udpPattern)
                .orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop), resolution.nextHops());
    }

    /**
     * The decision enforced for a data frame does not depend on the order in which the decisions are held by the PEP,
     * as the conflict resolution is deterministic.
     */
    @Test
    public void testResolutionIsIndependentOfTheOrderOfTheDecisions() {
        AccessDecision generalGrant = grant(this.ethernetPattern, this.firstNextHop, 60);
        AccessDecision specificDenial = deny(this.udpPattern, 60);

        DecisionResolution firstOrder = resolve(List.of(generalGrant, specificDenial), this.udpPattern).orElseThrow();
        DecisionResolution secondOrder = resolve(List.of(specificDenial, generalGrant), this.udpPattern).orElseThrow();
        assertEquals(firstOrder, secondOrder);
    }

    //
    // Step 2: The composite decision of conflicting decisions
    //

    /**
     * Two decisions of an equal flow pattern are conflicting, as neither of them matches a data frame more
     * specifically than the other. If both grant the data frame, the composite decision grants it and permits the
     * union of their next hops, as each granting decision independently permits its recipients.
     */
    @Test
    public void testCompositeDecisionOfEqualPatternsPermitsTheUnionOfTheNextHops() {
        AccessDecision firstGrant = grant(this.udpPattern, this.firstNextHop, 60);
        AccessDecision secondGrant = grant(this.udpPattern, this.secondNextHop, 60);

        DecisionResolution resolution = resolve(List.of(firstGrant, secondGrant), this.udpPattern).orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), resolution.nextHops());
    }

    /**
     * Two decisions whose flow patterns are incomparable are conflicting as well, although their patterns are not
     * equal. Their composite decision permits the union of their next hops.
     */
    @Test
    public void testCompositeDecisionOfIncomparablePatternsPermitsTheUnionOfTheNextHops() {
        AccessDecision firstGrant = grant(this.isolatedIpPattern, this.firstNextHop, 60);
        AccessDecision secondGrant = grant(this.ethernetPattern, this.secondNextHop, 60);

        DecisionResolution resolution = resolve(List.of(firstGrant, secondGrant), this.udpPattern).orElseThrow();
        assertTrue(resolution.isGranting());
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), resolution.nextHops());
    }

    /**
     * A composite decision grants a data frame only if all conflicting decisions grant it, i.e. a denying access
     * decision takes precedence over a granting one. The composite decision permits no recipient in that case, as a
     * denied data frame is dropped rather than forwarded.
     */
    @Test
    public void testCompositeDecisionDeniesIfOneConflictingDecisionDenies() {
        AccessDecision grant = grant(this.isolatedIpPattern, this.firstNextHop, 60);
        AccessDecision denial = deny(this.ethernetPattern, 60);

        DecisionResolution resolution = resolve(List.of(grant, denial), this.udpPattern).orElseThrow();
        assertFalse(resolution.isGranting());
        assertEquals(AccessDecision.Action.DENY, resolution.action());
        assertTrue(resolution.nextHops().isEmpty());
    }

    /**
     * A composite decision expires as soon as the first of the decisions it replaces expires, so that it is never
     * enforced beyond the period of validity of any of its constituents.
     */
    @Test
    public void testCompositeDecisionExpiresWithTheFirstOfItsConstituents() {
        AccessDecision longLived = grant(this.isolatedIpPattern, this.firstNextHop, 60);
        AccessDecision shortLived = grant(this.ethernetPattern, this.secondNextHop, 30);

        DecisionResolution resolution = resolve(List.of(longLived, shortLived), this.udpPattern).orElseThrow();
        assertEquals(shortLived.getValidUntil(), resolution.validUntil());
    }

    /**
     * Only the maximally specific decisions are combined into a composite decision. A more general denial is
     * discarded by the selection of the most specific decisions and therefore does not deny the data frame, although
     * a denial takes precedence within a composite decision.
     */
    @Test
    public void testCompositeDecisionCombinesTheMaximallySpecificDecisionsOnly() {
        AccessDecision firstGrant = grant(this.isolatedIpPattern, this.firstNextHop, 60);
        AccessDecision secondGrant = grant(this.ethernetPattern, this.secondNextHop, 60);
        AccessDecision generalDenial = deny(this.ethernetPattern, 60);

        // The denial shares the pattern of the second grant, so that it is maximally specific as well and denies.
        DecisionResolution denied = resolve(List.of(firstGrant, secondGrant, generalDenial), this.udpPattern)
                .orElseThrow();
        assertFalse(denied.isGranting());

        // A denial of a strictly more general pattern is discarded before the composite decision is formed.
        AccessDecision specificFirstGrant = grant(this.udpPattern, this.firstNextHop, 60);
        AccessDecision specificSecondGrant = grant(this.udpPattern, this.secondNextHop, 60);
        DecisionResolution granted = resolve(List.of(specificFirstGrant, specificSecondGrant, generalDenial),
                this.udpPattern).orElseThrow();
        assertTrue(granted.isGranting());
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), granted.nextHops());
    }

    /**
     * The maximally specific decisions of a set are those for which no other decision has a more specific flow
     * pattern. Of a specificity chain, exactly one decision is maximally specific, whereas two decisions of
     * incomparable patterns are both maximally specific and therefore conflicting.
     */
    @Test
    public void testMaximallySpecificDecisionsAreThoseWithoutAMoreSpecificAlternative() {
        AccessDecision udpGrant = grant(this.udpPattern, this.firstNextHop, 60);
        AccessDecision ipGrant = grant(this.ipPattern, this.firstNextHop, 60);
        AccessDecision isolatedIpGrant = grant(this.isolatedIpPattern, this.firstNextHop, 60);
        AccessDecision ethernetGrant = grant(this.ethernetPattern, this.secondNextHop, 60);

        assertEquals(List.of(udpGrant),
                DecisionResolver.getMaximallySpecificDecisions(List.of(udpGrant, ipGrant, ethernetGrant)));
        assertEquals(List.of(isolatedIpGrant, ethernetGrant),
                DecisionResolver.getMaximallySpecificDecisions(List.of(isolatedIpGrant, ethernetGrant)));
    }

    /**
     * A composite decision requires at least one access decision, as it is defined for two or more conflicting
     * decisions and has no meaning for an empty set.
     */
    @Test
    public void testCompositeDecisionOfAnEmptySetIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> DecisionResolver.constructCompositeResolution(List.of()));
    }

    //
    // Test fixture
    //

    private Optional<DecisionResolution> resolve(Collection<AccessDecision> decisions,
                                                 AccessRequestPattern requestPattern) {
        return DecisionResolver.getResolution(decisions, requestPattern, this.now);
    }

    private AccessDecision grant(AccessRequestPattern pattern, InetAddress nextHop, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.GRANT, Set.of(nextHop),
                this.now.plusSeconds(validitySeconds));
    }

    private AccessDecision deny(AccessRequestPattern pattern, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.DENY, Set.of(),
                this.now.plusSeconds(validitySeconds));
    }

    private AccessDecision notApplicable(AccessRequestPattern pattern, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.NOTAPPLICABLE, Set.of(),
                this.now.plusSeconds(validitySeconds));
    }
}
