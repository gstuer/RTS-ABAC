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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the decision cache of a policy enforcement point (PEP), i.e. the local session state it keeps for one
 * direction of the data frames it enforces.
 */
public class DecisionCacheTest {
    private DecisionCache cache;
    private AccessRequestPattern ethernetPattern;
    private AccessRequestPattern udpPattern;
    private InetAddress firstNextHop;
    private InetAddress secondNextHop;

    @BeforeEach
    public void setUp() throws Exception {
        this.cache = new DecisionCache();
        this.ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        AccessRequestPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"),
                InetAddress.getByName("255.255.255.255"), IpNumber.UDP, this.ethernetPattern);
        this.udpPattern = new UdpPattern(10000, 10001, ipPattern);
        this.firstNextHop = InetAddress.getByName("127.0.0.10");
        this.secondNextHop = InetAddress.getByName("127.0.0.11");
    }

    //
    // Supersession and removal of access decisions
    //

    /**
     * The renewed access decision of a policy supersedes its predecessor instead of accumulating next to it. Without
     * the supersession, the cache would grow by one decision per renewal, i.e. by the runtime of the PEP divided by
     * the period of validity of the policy, and the resolution of every data frame would scan all of them.
     */
    @Test
    public void testRenewedDecisionSupersedesItsPredecessor() {
        for (int renewal = 0; renewal < 100; renewal++) {
            this.cache.addDecision(grant(this.ethernetPattern, this.firstNextHop, 60));
        }

        assertEquals(1, this.cache.getDecisionCount(),
                "A decision that authorizes equally to a cached one supersedes it.");
        assertTrue(this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow().isGranting());
    }

    /**
     * Two access decisions of an equal flow pattern that authorize differently are both retained, as the conflict
     * between them is resolved per data frame rather than by the cache.
     */
    @Test
    public void testDecisionsOfEqualPatternAndDeviatingAuthorizationAreRetained() {
        this.cache.addDecision(grant(this.ethernetPattern, this.firstNextHop, 60));
        this.cache.addDecision(grant(this.ethernetPattern, this.secondNextHop, 60));
        this.cache.addDecision(new AccessDecision(this.ethernetPattern, AccessDecision.Action.NOTAPPLICABLE,
                Set.of(), Instant.now().plusSeconds(60)));

        assertEquals(3, this.cache.getDecisionCount());
        DecisionResolution resolution = this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow();
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), resolution.nextHops(),
                "The conflicting decisions are resolved into their composite decision.");
    }

    /**
     * The later period of validity prevails when a decision supersedes a cached one, so that a session
     * initialization that arrives out of order cannot shorten the validity of a decision already enforced.
     */
    @Test
    public void testSupersessionKeepsTheLaterPeriodOfValidity() {
        AccessDecision longLived = grant(this.ethernetPattern, this.firstNextHop, 600);
        AccessDecision shortLived = grant(this.ethernetPattern, this.firstNextHop, 60);

        this.cache.addDecision(longLived);
        this.cache.addDecision(shortLived);

        assertEquals(1, this.cache.getDecisionCount());
        assertEquals(longLived.getValidUntil(),
                this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow().validUntil());
    }

    /**
     * An access decision whose period of validity has elapsed is removed from the cache, so that the cache of a flow
     * that is no longer renewed does not retain its decisions indefinitely. A decision that is already expired when
     * it is added is not retained either.
     */
    @Test
    public void testExpiredDecisionIsRemoved() {
        this.cache.addDecision(grant(this.ethernetPattern, this.firstNextHop, -1));
        assertEquals(0, this.cache.getDecisionCount(), "An expired decision is not retained.");

        // A decision that expires while it is cached is removed by the next write
        AccessDecision expiring = new AccessDecision(this.ethernetPattern, AccessDecision.Action.GRANT,
                Set.of(this.firstNextHop), Instant.now().plusMillis(1));
        this.cache.addDecision(expiring);
        assertEquals(1, this.cache.getDecisionCount());
        Thread.onSpinWait();
        while (expiring.isValid()) {
            Thread.onSpinWait();
        }
        this.cache.addDecision(grant(this.udpPattern, this.secondNextHop, 60));

        assertEquals(1, this.cache.getDecisionCount());
        assertEquals(Set.of(this.secondNextHop),
                this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow().nextHops());
    }

    //
    // Memoisation of the resolution of a flow
    //

    /**
     * The resolution of a flow is memoised, as the decisions of a flow change only when a session initialization
     * arrives or when one of them expires. The resolution of a data frame is therefore derived once per flow rather
     * than once per data frame.
     */
    @Test
    public void testResolutionOfAFlowIsMemoized() {
        this.cache.addDecision(grant(this.ethernetPattern, this.firstNextHop, 60));
        assertEquals(0, this.cache.getResolutionCount());

        DecisionResolution resolution = this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow();
        assertEquals(1, this.cache.getResolutionCount());
        assertEquals(resolution, this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow(),
                "The memoised resolution is the resolution the decisions yield.");
        assertEquals(1, this.cache.getResolutionCount());
    }

    /**
     * The absence of a resolution is memoised as well, as it changes only once an access decision is added. A PEP
     * therefore scans its decisions once per unknown flow rather than once per data frame of that flow.
     */
    @Test
    public void testAbsentResolutionIsMemoized() {
        assertTrue(this.cache.getResolution(this.udpPattern, Instant.now()).isEmpty());

        assertEquals(1, this.cache.getResolutionCount());
        assertTrue(this.cache.getResolution(this.udpPattern, Instant.now()).isEmpty());
    }

    /**
     * An added access decision discards the memoised resolutions, as it may change the resolution of any flow it
     * matches. A memoised resolution must never outlive the decisions it was derived from.
     */
    @Test
    public void testAddedDecisionDiscardsTheMemoizedResolutions() {
        this.cache.addDecision(grant(this.ethernetPattern, this.firstNextHop, 60));
        assertTrue(this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow().isGranting());
        assertEquals(1, this.cache.getResolutionCount());

        // A denial of the same flow pattern is conflicting, so that the composite decision denies the data frame
        this.cache.addDecision(new AccessDecision(this.ethernetPattern, AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60)));

        assertEquals(0, this.cache.getResolutionCount(), "An added decision discards the memoised resolutions.");
        assertFalse(this.cache.getResolution(this.udpPattern, Instant.now()).orElseThrow().isGranting());
    }

    /**
     * A memoised resolution is not used beyond its period of validity, which is the earliest expiry among the
     * decisions it was derived from. The resolution is then derived anew from the decisions that are still valid.
     */
    @Test
    public void testMemoizedResolutionIsNotUsedBeyondItsValidity() {
        Instant now = Instant.now();
        this.cache.addDecision(grant(this.ethernetPattern, this.firstNextHop, 30));
        this.cache.addDecision(grant(this.ethernetPattern, this.secondNextHop, 600));

        DecisionResolution resolution = this.cache.getResolution(this.udpPattern, now).orElseThrow();
        assertEquals(Set.of(this.firstNextHop, this.secondNextHop), resolution.nextHops());

        // After the first of the two decisions expired, only the second one governs the data frames of the flow
        DecisionResolution laterResolution = this.cache.getResolution(this.udpPattern, now.plusSeconds(60))
                .orElseThrow();
        assertEquals(Set.of(this.secondNextHop), laterResolution.nextHops(),
                "An expired decision must not be enforced through a memoised resolution.");
    }

    private static AccessDecision grant(AccessRequestPattern pattern, InetAddress nextHop, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.GRANT, Set.of(nextHop),
                Instant.now().plusSeconds(validitySeconds));
    }
}
