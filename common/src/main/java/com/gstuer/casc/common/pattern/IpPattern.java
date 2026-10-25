package com.gstuer.casc.common.pattern;

import com.google.common.primitives.Bytes;
import org.pcap4j.packet.namednumber.IpNumber;

import java.net.InetAddress;
import java.util.Objects;

public class IpPattern extends AccessRequestPattern {
    private final InetAddress source;
    private final InetAddress destination;
    private final IpNumber protocol;

    public IpPattern(InetAddress source, InetAddress destination, IpNumber protocol) {
        this(source, destination, protocol, null);
    }

    public IpPattern(InetAddress source, InetAddress destination, IpNumber protocol, AccessRequestPattern enclosedPattern) {
        super(enclosedPattern);
        this.source = source;
        this.destination = destination;
        this.protocol = protocol;
    }

    public InetAddress getSource() {
        return this.source;
    }

    public InetAddress getDestination() {
        return this.destination;
    }

    public IpNumber getProtocol() {
        return this.protocol;
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
        IpPattern that = (IpPattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.protocol, that.protocol);
    }

    @Override
    public boolean equalsIsolated(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        IpPattern that = (IpPattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.protocol, that.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), source, destination, protocol);
    }

    @Override
    public byte[] getSigningData() {
        // The signing data covers the enclosed pattern as well, as this pattern constrains the protocol layers
        // beneath the IP layer through it. Without them, a decision for one link layer flow would be signed
        // identically to a decision for another one.
        return Bytes.concat(source.getAddress(), destination.getAddress(), new byte[]{protocol.value()},
                super.getSigningData());
    }
}
