package com.gstuer.casc.common.message;

import com.google.common.primitives.Bytes;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Set;

public class AttributeExchangeRequestMessage extends AccessControlMessage<Set<AttributeIdentifier>> {
    @Serial
    private static final long serialVersionUID = 1806760682714942195L;

    public AttributeExchangeRequestMessage(InetAddress source, InetAddress destination, DigitalSignature signature, Set<AttributeIdentifier> identifiers) {
        super(source, destination, signature, identifiers);
    }

    public AttributeExchangeRequestMessage(InetAddress destination, DigitalSignature signature, Set<AttributeIdentifier> identifiers) {
        super(destination, signature, identifiers);
    }

    @Override
    public AttributeExchangeRequestMessage fromSource(InetAddress source) {
        return new AttributeExchangeRequestMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AttributeExchangeRequestMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AttributeExchangeRequestMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        return this.getPayload().parallelStream()
                .map(AttributeIdentifier::getSigningData)
                .reduce(Bytes::concat)
                .orElse(new byte[0]);
    }

    @Override
    public String toString() {
        try {
            return new JsonProcessor().convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
