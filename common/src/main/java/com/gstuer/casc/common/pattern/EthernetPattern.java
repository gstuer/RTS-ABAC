package com.gstuer.casc.common.pattern;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Shorts;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.util.Objects;

public class EthernetPattern extends AccessRequestPattern {
    private final MacAddress source;
    private final MacAddress destination;
    private final EtherType etherType;

    public EthernetPattern(MacAddress sourceAddress, MacAddress destinationAddress, EtherType etherType) {
        this(sourceAddress, destinationAddress, etherType, null);
    }

    public EthernetPattern(MacAddress sourceAddress, MacAddress destinationAddress, EtherType etherType, AccessRequestPattern enclosedPattern) {
        super(enclosedPattern);
        this.source = Objects.requireNonNull(sourceAddress);
        this.destination = Objects.requireNonNull(destinationAddress);
        this.etherType = etherType;
    }

    public MacAddress getSource() {
        return this.source;
    }

    public MacAddress getDestination() {
        return this.destination;
    }

    public EtherType getEtherType() {
        return this.etherType;
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
        EthernetPattern that = (EthernetPattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.etherType.value(), that.etherType.value());
    }

    @Override
    public boolean equalsIsolated(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        EthernetPattern that = (EthernetPattern) object;
        return Objects.equals(this.source, that.source) && Objects.equals(this.destination, that.destination)
                && Objects.equals(this.etherType.value(), that.etherType.value());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), source, destination, etherType);
    }

    @Override
    public byte[] getSigningData() {
        // The signing data covers the enclosed pattern as well, so that every pattern of a flow pattern chain
        // contributes to the signature of an access decision.
        return Bytes.concat(source.getAddress(), destination.getAddress(), Shorts.toByteArray(etherType.value()),
                super.getSigningData());
    }
}
