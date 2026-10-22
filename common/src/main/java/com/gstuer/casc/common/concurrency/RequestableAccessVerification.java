package com.gstuer.casc.common.concurrency;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Represents the access decision that a verifying policy decision point (PDP) holds for a flow pattern, requested by
 * a policy enforcement point (PEP) to verify a session initialization.
 */
public class RequestableAccessVerification extends RequestableResource<AccessDecision> {
    private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(250);
    private static final int REQUEST_RETRIES = 3;

    private final AccessRequestPattern pattern;

    public RequestableAccessVerification(BlockingQueue<AccessControlMessage<?>> messageEgress, Signer<?> signer,
                                         InetAddress verificationProvider, AccessRequestPattern pattern) {
        super(messageEgress, signer, REQUEST_RETRIES, REQUEST_TIMEOUT_NANOS, verificationProvider);
        this.pattern = Objects.requireNonNull(pattern);
    }

    public AccessRequestPattern getPattern() {
        return this.pattern;
    }

    @Override
    protected AccessControlMessage<?> constructRequestMessage() {
        try {
            return new AccessVerificationRequestMessage(this.getProvider(), null, this.pattern).sign(this.getSigner());
        } catch (InvalidKeyException | SignatureException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    protected void sendRequestMessage() {
        super.sendRequestMessage();
        System.out.printf("[Request] Access decision verification request sent to %s.\n",
                this.getProvider().getHostAddress());
    }
}
