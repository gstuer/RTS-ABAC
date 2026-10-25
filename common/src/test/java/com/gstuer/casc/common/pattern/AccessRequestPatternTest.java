package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentSkipListSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class AccessRequestPatternTest {
    @Test
    public void testNaturalOrdering() throws UnknownHostException {
        // Test data
        SortedSet<AccessRequestPattern> set = new ConcurrentSkipListSet<>();
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);
        AccessRequestPattern udpPattern = new UdpPattern(10000, 10001, ipPattern);

        // Execution
        set.add(ipPattern);
        set.add(ethernetPattern);
        set.add(udpPattern);

        // Assertions
        //// Most specific pattern first
        assertEquals(udpPattern, set.first());
        assertEquals(ethernetPattern, set.last());
    }

    /**
     * The signing data of a flow pattern determines the pattern, i.e. two unequal patterns never yield equal signing
     * data. The signature of an access decision would otherwise not bind the decision to its flow pattern, so that a
     * decision signed for one flow would be a validly signed decision for another one. The patterns of the test
     * differ in the layer they constrain, in the transport protocol, in an enclosed pattern, and in the presence of
     * an enclosed pattern, which covers every pattern class and the inheritance of the signing data along a chain.
     */
    @Test
    public void testSigningDataDeterminesThePattern() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:01"),
                MacAddress.getByName("00:00:00:00:00:02"), EtherType.IPV4);
        EthernetPattern deviatingEthernetPattern = new EthernetPattern(MacAddress.getByName("aa:aa:aa:aa:aa:aa"),
                MacAddress.getByName("bb:bb:bb:bb:bb:bb"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"),
                IpNumber.UDP, ethernetPattern);
        List<AccessRequestPattern> patterns = List.of(
                ethernetPattern,
                deviatingEthernetPattern,
                ipPattern,
                new IpPattern(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"), IpNumber.UDP,
                        deviatingEthernetPattern),
                new IpPattern(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"), IpNumber.UDP),
                new UdpPattern(10000, 10001, ipPattern),
                new UdpPattern(10000, 10001, null),
                new TcpPattern(10000, 10001, ipPattern),
                new TcpPattern(10000, 10001, null));

        // Assertions
        for (AccessRequestPattern pattern : patterns) {
            for (AccessRequestPattern otherPattern : patterns) {
                if (pattern == otherPattern) {
                    continue;
                }
                assertNotEquals(pattern, otherPattern, "The patterns of the test have to be pairwise unequal.");
                assertFalse(Arrays.equals(pattern.getSigningData(), otherPattern.getSigningData()),
                        "Unequal patterns must not yield equal signing data: %s and %s"
                                .formatted(pattern.getClass().getSimpleName(),
                                        otherPattern.getClass().getSimpleName()));
            }
        }
    }
}
