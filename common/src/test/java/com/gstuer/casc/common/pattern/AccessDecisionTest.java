package com.gstuer.casc.common.pattern;

import com.gstuer.casc.common.AccessDecision;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentSkipListSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AccessDecisionTest {
    @Test
    public void testNaturalOrderingGrantedDecisions() throws UnknownHostException {
        // Test data
        SortedSet<AccessDecision> set = new ConcurrentSkipListSet<>();
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);
        AccessRequestPattern udpPattern = new UdpPattern(10000, 10001, ipPattern);

        Instant now = Instant.now();
        AccessDecision udpDecision = new AccessDecision(udpPattern, AccessDecision.Action.GRANT, Set.of(), now);
        AccessDecision ipDecision = new AccessDecision(ipPattern, AccessDecision.Action.GRANT, Set.of(), now);
        AccessDecision ethernetDecision = new AccessDecision(ethernetPattern, AccessDecision.Action.GRANT, Set.of(), now);

        // Execution
        set.add(ipDecision);
        set.add(ethernetDecision);
        set.add(udpDecision);

        // Assertions
        //// Least specific decision first
        assertEquals(udpDecision, set.first());
        assertEquals(ethernetDecision, set.last());
    }

    @Test
    public void testNaturalOrderingDeniedDecisions() throws UnknownHostException {
        // Test data
        SortedSet<AccessDecision> set = new ConcurrentSkipListSet<>();
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);
        AccessRequestPattern udpPattern = new UdpPattern(10000, 10001, ipPattern);

        Instant now = Instant.now();
        AccessDecision udpDecision = new AccessDecision(udpPattern, AccessDecision.Action.DENY, Set.of(), now);
        AccessDecision ipDecision = new AccessDecision(ipPattern, AccessDecision.Action.DENY, Set.of(), now);
        AccessDecision ethernetDecision = new AccessDecision(ethernetPattern, AccessDecision.Action.DENY, Set.of(), now);

        // Execution
        set.add(ipDecision);
        set.add(ethernetDecision);
        set.add(udpDecision);

        // Assertions
        //// Most specific decision first
        assertEquals(udpDecision, set.first());
        assertEquals(ethernetDecision, set.last());
    }

    @Test
    public void testNaturalOrderingSamePatternsMixedActions() throws UnknownHostException {
        // Test data
        SortedSet<AccessDecision> firstSet = new ConcurrentSkipListSet<>();
        SortedSet<AccessDecision> secondSet = new ConcurrentSkipListSet<>();
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);
        AccessRequestPattern udpPattern = new UdpPattern(10000, 10001, ipPattern);

        Instant now = Instant.now();
        AccessDecision denyDecision = new AccessDecision(udpPattern, AccessDecision.Action.DENY, Set.of(), now);
        AccessDecision grantDecision = new AccessDecision(udpPattern, AccessDecision.Action.GRANT, Set.of(), now);

        // Execution
        firstSet.add(denyDecision);
        firstSet.add(grantDecision);
        secondSet.add(grantDecision);
        secondSet.add(denyDecision);

        // Assertions
        assertEquals(denyDecision, firstSet.first());
        assertEquals(denyDecision, secondSet.first());
        assertEquals(grantDecision, firstSet.last());
        assertEquals(grantDecision, secondSet.last());
    }

    @Test
    public void testNaturalOrderingMixedPatternsMixedActions() throws UnknownHostException {
        // Test data
        SortedSet<AccessDecision> set = new ConcurrentSkipListSet<>();
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);
        IpPattern ipPatternIsolated = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        AccessRequestPattern udpPattern = new UdpPattern(10000, 10001, ipPattern);

        Instant now = Instant.now();
        AccessDecision grantUdpDecision = new AccessDecision(udpPattern, AccessDecision.Action.GRANT, Set.of(), now);
        AccessDecision grantIpDecision = new AccessDecision(ipPattern, AccessDecision.Action.GRANT, Set.of(), now);
        AccessDecision denyIpIsolatedDecision = new AccessDecision(ipPatternIsolated, AccessDecision.Action.DENY, Set.of(), now);
        AccessDecision grantEthernetDecision = new AccessDecision(ethernetPattern, AccessDecision.Action.GRANT, Set.of(), now);

        // Execution
        set.add(grantEthernetDecision);
        set.add(grantIpDecision);
        set.add(grantUdpDecision);
        set.add(denyIpIsolatedDecision);

        // Assertions
        Object[] decisions = set.toArray();
        assertEquals(grantUdpDecision, decisions[0]);
        assertEquals(grantIpDecision, decisions[1]);
        assertEquals(denyIpIsolatedDecision, decisions[2]);
        assertEquals(grantEthernetDecision, decisions[3]);
    }
}
