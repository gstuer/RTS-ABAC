package com.gstuer.casc.pdp.attribute;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.concurrency.RequestableResource;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class RequestablePolicyAttribute extends RequestableResource<PolicyAttribute<?>> {
    private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(250);
    private static final int REQUEST_RETRIES = 3;

    private final AttributeIdentifier identifier;

    public RequestablePolicyAttribute(BlockingQueue<AccessControlMessage<?>> messageEgress, Signer<?> signer,
                                      AttributeIdentifier identifier) {
        super(messageEgress, signer, REQUEST_RETRIES, REQUEST_TIMEOUT_NANOS, identifier.getProvider());
        this.identifier = Objects.requireNonNull(identifier);
    }

    public AttributeIdentifier getIdentifier() {
        return identifier;
    }

    @Override
    protected AccessControlMessage<?> constructRequestMessage() {
        try {
            return new AttributeExchangeRequestMessage(this.getProvider(), null, Set.of(this.identifier))
                    .sign(this.getSigner());
        } catch (InvalidKeyException | SignatureException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    protected void sendRequestMessage() {
        super.sendRequestMessage();
        System.out.printf("[Request] Attribute request for \"%s\" sent to %s.\n", this.identifier.getName(),
                this.getProvider().getHostAddress());
    }
}
