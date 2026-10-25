package com.gstuer.casc.common.pattern;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class IpPatternTest {
    @Test
    public void testContainsEqual() throws UnknownHostException {
        // Test data
        IpPattern firstPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        IpPattern secondPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);

        // Assertion
        assertTrue(firstPattern.contains(firstPattern));
        assertTrue(firstPattern.contains(secondPattern));
        assertTrue(secondPattern.contains(firstPattern));
        assertTrue(secondPattern.contains(secondPattern));
    }

    @Test
    public void testContainsUnequal() throws UnknownHostException {
        // Test data
        IpPattern firstPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        IpPattern secondPattern = new IpPattern(InetAddress.getByName("127.0.0.2"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP);
        IpPattern thirdPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("254.255.255.255"), IpNumber.TCP);
        IpPattern fourthPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.UDP);

        // Assertion
        assertFalse(firstPattern.contains(secondPattern));
        assertFalse(firstPattern.contains(thirdPattern));
        assertFalse(firstPattern.contains(fourthPattern));

        assertFalse(secondPattern.contains(firstPattern));
        assertFalse(secondPattern.contains(thirdPattern));
        assertFalse(secondPattern.contains(fourthPattern));

        assertFalse(thirdPattern.contains(firstPattern));
        assertFalse(thirdPattern.contains(secondPattern));
        assertFalse(thirdPattern.contains(fourthPattern));

        assertFalse(fourthPattern.contains(firstPattern));
        assertFalse(fourthPattern.contains(secondPattern));
        assertFalse(fourthPattern.contains(thirdPattern));
    }

    @Test
    public void testContainsEqualEthernetEnclosed() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernet = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern firstIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, firstEthernet);
        EthernetPattern secondEthernet = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern secondIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, secondEthernet);

        // Assertion
        assertTrue(firstIP.contains(firstIP));
        assertTrue(firstIP.contains(secondIP));
        assertTrue(secondIP.contains(firstIP));
        assertTrue(secondIP.contains(secondIP));
    }


    @Test
    public void testContainsUnequalEthernetEnclosed() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernet = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern firstIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, firstEthernet);
        EthernetPattern secondEthernet = new EthernetPattern(MacAddress.getByName("ff:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern secondIP = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, secondEthernet);

        // Assertion
        assertFalse(firstIP.contains(secondIP));
        assertFalse(secondIP.contains(firstIP));
    }

    @Test
    public void testContainsEnclosedPattern() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern ipPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, ethernetPattern);

        // Assertion
        assertTrue(ipPattern.contains(ethernetPattern));
        assertFalse(ethernetPattern.contains(ipPattern));
    }

    @Test
    public void testContainsEnclosedPatternTransitive() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern outerIpPattern = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, ethernetPattern);
        IpPattern innerIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, outerIpPattern);

        // Assertion
        assertTrue(innerIpPattern.contains(outerIpPattern));
        assertTrue(outerIpPattern.contains(ethernetPattern));
        assertTrue(innerIpPattern.contains(ethernetPattern));
    }

    @Test
    public void testContainsIsolatedEnclosedPattern() throws UnknownHostException {
        // Test data
        EthernetPattern ethernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern outerIpPattern = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, ethernetPattern);
        IpPattern innerIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, outerIpPattern);

        IpPattern outerIpPatternIsolated = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, null);

        // Assertion
        assertTrue(innerIpPattern.contains(outerIpPatternIsolated));
        assertTrue(outerIpPattern.contains(outerIpPatternIsolated));

        assertFalse(outerIpPatternIsolated.contains(innerIpPattern));
        assertFalse(outerIpPatternIsolated.contains(outerIpPattern));
    }

    @Test
    public void testContainsEnclosedPatternUnequalSubtree() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern outerIpPattern = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, firstEthernetPattern);
        IpPattern innerIpPattern = new IpPattern(InetAddress.getByName("127.0.0.1"), InetAddress.getByName("255.255.255.255"), IpNumber.TCP, outerIpPattern);

        EthernetPattern secondEthernetPattern = new EthernetPattern(MacAddress.getByName("ff:00:00:00:00:00"), MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        IpPattern outerIpPatternDifferentSubtree = new IpPattern(InetAddress.getByName("192.168.0.1"), InetAddress.getByName("192.168.0.2"), IpNumber.IPV4, secondEthernetPattern);

        // Assertion
        assertNotEquals(firstEthernetPattern, secondEthernetPattern);
        assertFalse(innerIpPattern.contains(outerIpPatternDifferentSubtree));
        assertFalse(outerIpPattern.contains(outerIpPatternDifferentSubtree));
    }

    /**
     * The signing data of a flow pattern covers its enclosed patterns, so that two patterns which differ only in an
     * enclosed pattern yield different signing data. Otherwise the signature of an access decision would not bind
     * the decision to the protocol layers beneath the outermost one, and a decision signed for one link layer flow
     * would be a validly signed decision for another one.
     */
    @Test
    public void testSigningDataCoversTheEnclosedPattern() throws UnknownHostException {
        // Test data
        EthernetPattern firstEthernetPattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:01"),
                MacAddress.getByName("00:00:00:00:00:02"), EtherType.IPV4);
        EthernetPattern secondEthernetPattern = new EthernetPattern(MacAddress.getByName("aa:aa:aa:aa:aa:aa"),
                MacAddress.getByName("bb:bb:bb:bb:bb:bb"), EtherType.IPV4);
        IpPattern firstPattern = new IpPattern(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"),
                IpNumber.TCP, firstEthernetPattern);
        IpPattern secondPattern = new IpPattern(InetAddress.getByName("10.0.0.1"), InetAddress.getByName("10.0.0.2"),
                IpNumber.TCP, secondEthernetPattern);
        IpPattern isolatedPattern = new IpPattern(InetAddress.getByName("10.0.0.1"),
                InetAddress.getByName("10.0.0.2"), IpNumber.TCP);

        // Assertion
        assertFalse(Arrays.equals(firstPattern.getSigningData(), secondPattern.getSigningData()),
                "Patterns of two different link layer flows must not be signed identically.");
        assertFalse(Arrays.equals(firstPattern.getSigningData(), isolatedPattern.getSigningData()),
                "A pattern constraining the link layer must not be signed as one that does not constrain it.");
        assertArrayEquals(firstEthernetPattern.getSigningData(),
                Arrays.copyOfRange(firstPattern.getSigningData(), 9, firstPattern.getSigningData().length),
                "The signing data of the enclosed pattern is appended to the one of the enclosing pattern.");
    }
}
