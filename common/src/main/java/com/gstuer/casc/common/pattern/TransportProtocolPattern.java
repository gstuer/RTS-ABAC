package com.gstuer.casc.common.pattern;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import org.pcap4j.packet.namednumber.IpNumber;

import java.util.Objects;

public abstract class TransportProtocolPattern extends AccessRequestPattern {
    private final int sourcePort;
    private final int destinationPort;

    protected TransportProtocolPattern(int sourcePort, int destinationPort, AccessRequestPattern enclosedPattern) {
        super(enclosedPattern);
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        if (!super.equals(object)) {
            return false;
        }
        TransportProtocolPattern that = (TransportProtocolPattern) object;
        return sourcePort == that.sourcePort && destinationPort == that.destinationPort;
    }

    @Override
    public boolean equalsIsolated(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        TransportProtocolPattern that = (TransportProtocolPattern) object;
        return sourcePort == that.sourcePort && destinationPort == that.destinationPort;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), sourcePort, destinationPort);
    }

    @Override
    public byte[] getSigningData() {
        // The transport protocol and the enclosed pattern are part of the signing data, as two patterns of
        // different transport protocols constrain different data frames although they constrain an equal pair of
        // ports, and as this pattern constrains the protocol layers beneath the transport layer through its
        // enclosed pattern.
        return Bytes.concat(new byte[]{this.getTransportProtocol().value()}, Ints.toByteArray(sourcePort),
                Ints.toByteArray(destinationPort), super.getSigningData());
    }

    /**
     * Gets the transport protocol constrained by this pattern. It is part of the identity of a pattern, as two
     * patterns of different transport protocols are unequal even if they constrain an equal pair of ports.
     *
     * @return the transport protocol of this pattern.
     */
    protected abstract IpNumber getTransportProtocol();
}
