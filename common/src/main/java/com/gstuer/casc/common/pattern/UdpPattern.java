package com.gstuer.casc.common.pattern;

import org.pcap4j.packet.namednumber.IpNumber;

public class UdpPattern extends TransportProtocolPattern {
    public UdpPattern(int sourcePort, int destinationPort, AccessRequestPattern enclosedPattern) {
        super(sourcePort, destinationPort, enclosedPattern);
    }

    @Override
    protected IpNumber getTransportProtocol() {
        return IpNumber.UDP;
    }
}
