package com.gstuer.casc.common.message;

import com.google.common.primitives.Bytes;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Set;

public class AttributeExchangeMessage extends AccessControlMessage<Set<PolicyAttribute<?>>> {
    @Serial
    private static final long serialVersionUID = 682215083300541220L;

    public AttributeExchangeMessage(InetAddress source, InetAddress destination, DigitalSignature signature, Set<PolicyAttribute<?>> attributes) {
        super(source, destination, signature, attributes);
    }

    public AttributeExchangeMessage(InetAddress destination, DigitalSignature signature, Set<PolicyAttribute<?>> attributes) {
        super(destination, signature, attributes);
    }

    @Override
    public AttributeExchangeMessage fromSource(InetAddress source) {
        return new AttributeExchangeMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AttributeExchangeMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AttributeExchangeMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        return this.getPayload().parallelStream()
                .map(PolicyAttribute::getSigningData)
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
