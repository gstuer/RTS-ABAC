package com.gstuer.casc.common;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.numeric.LongOperator;
import com.gstuer.casc.common.attribute.predicate.numeric.UnivariateNumericPredicate;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the dynamic authorization function, i.e. the derivation of an access decision from an access control policy
 * for a given system state. The policy of the tests is the dynamic policy of the running example: a flow is granted
 * as long as an AASP reports that no intrusion was detected.
 */
public class AccessPolicyTest {
    private AccessRequestPattern flowPattern;
    private AttributeIdentifier identifier;
    private PolicyPredicate predicate;
    private InetAddress nextHop;

    @BeforeEach
    public void setUp() throws Exception {
        this.flowPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        this.identifier = new AttributeIdentifier("intruded", InetAddress.getByName("127.0.0.2"));
        this.predicate = new UnivariateNumericPredicate<>(this.identifier, LongOperator.EQUAL, 0L);
        this.nextHop = InetAddress.getByName("127.0.0.4");
    }

    /**
     * If the auxiliary predicates of a policy match the system state, the derived decision states the action and the
     * next hops of the policy. Its period of validity is the one of the attribute value the predicate was evaluated
     * against, as the AASP vouches for that value for that period only.
     */
    @Test
    public void testApplicablePolicyYieldsItsActionAndNextHops() {
        PolicyAttribute<?> attribute = this.attribute(0L, Duration.ofSeconds(5));
        AccessPolicy policy = new AccessPolicy(this.flowPattern, AccessDecision.Action.GRANT, this.nextHop,
                this.predicate);

        AccessDecision decision = policy.evaluate(Map.of(this.identifier, attribute));

        assertTrue(decision.isGranting());
        assertEquals(Set.of(this.nextHop), decision.getNextHops());
        assertEquals(this.flowPattern, decision.getPattern());
        assertEquals(attribute.getValidUntil(), decision.getValidUntil(),
                "The decision inherits the period of validity of the attribute value.");
    }

    /**
     * If the auxiliary predicates do not match the system state, the policy is not applicable: the derived decision
     * neither grants nor denies the matching data frames and permits no recipient, so that it does not override an
     * applicable policy of the same flow.
     */
    @Test
    public void testNonMatchingPredicateYieldsANonApplicableDecision() {
        PolicyAttribute<?> attribute = this.attribute(1L, Duration.ofSeconds(5));
        AccessPolicy policy = new AccessPolicy(this.flowPattern, AccessDecision.Action.GRANT, this.nextHop,
                this.predicate);

        AccessDecision decision = policy.evaluate(Map.of(this.identifier, attribute));

        assertFalse(decision.isApplicable());
        assertFalse(decision.isDenying(), "A non-applicable decision must not deny, as it would override a grant.");
        assertTrue(decision.getNextHops().isEmpty());
        assertEquals(attribute.getValidUntil(), decision.getValidUntil());
    }

    /**
     * While the attributes of a policy are being fetched from their AASPs, or while an AASP is unreachable, no
     * decision can be derived from the system state. The policy is then not applicable, but only briefly, so that
     * the PDP derives a decision from the attribute values as soon as they arrive instead of treating the policy as
     * non-applicable for a full period of validity.
     */
    @Test
    public void testUnavailableAttributeYieldsAShortLivedNonApplicableDecision() {
        AccessPolicy policy = new AccessPolicy(this.flowPattern, AccessDecision.Action.GRANT, this.nextHop,
                this.predicate);

        AccessDecision decision = policy.evaluate(Map.of());

        assertFalse(decision.isApplicable());
        assertTrue(decision.isValid(), "The decision is valid, so that the data frames of the flow are dropped.");
        assertTrue(decision.getValidUntil().isBefore(Instant.now().plusSeconds(1)),
                "A decision derived without the required attributes has to be renewed within a second.");
    }

    private PolicyAttribute<?> attribute(long value, Duration validity) {
        return new LongAttribute(this.identifier, Instant.now(), validity, value);
    }
}
