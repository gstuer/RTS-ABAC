package com.gstuer.casc.common.pattern;

import org.pcap4j.packet.namednumber.IpNumber;

public class TcpPattern extends TransportProtocolPattern {
    public TcpPattern(int sourcePort, int destinationPort, AccessRequestPattern enclosedPattern) {
        super(sourcePort, destinationPort, enclosedPattern);
    }

    @Override
    protected IpNumber getTransportProtocol() {
        return IpNumber.TCP;
    }
}
