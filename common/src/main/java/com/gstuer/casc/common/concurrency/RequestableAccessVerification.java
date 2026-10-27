package com.gstuer.casc.common.concurrency;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Represents the verdicts that a verifying policy decision point (PDP) holds for the access decisions of a session
 * initialization, requested by a policy enforcement point (PEP) to verify that session initialization.
 */
public class RequestableAccessVerification extends RequestableResource<List<AccessDecisionVerdict>> {
    private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(250);
    private static final int REQUEST_RETRIES = 3;

    private final List<AccessDecision> decisions;

    public RequestableAccessVerification(BlockingQueue<AccessControlMessage<?>> messageEgress, Signer<?> signer,
                                         InetAddress verificationProvider, List<AccessDecision> decisions) {
        super(messageEgress, signer, REQUEST_RETRIES, REQUEST_TIMEOUT_NANOS, verificationProvider);
        this.decisions = List.copyOf(Objects.requireNonNull(decisions));
    }

    public List<AccessDecision> getDecisions() {
        return this.decisions;
    }

    @Override
    protected AccessControlMessage<?> constructRequestMessage() {
        try {
            return new AccessVerificationRequestMessage(this.getProvider(), null, this.decisions)
                    .sign(this.getSigner());
        } catch (InvalidKeyException | SignatureException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Override
    protected void sendRequestMessage() {
        super.sendRequestMessage();
        System.out.printf("[Request] Access decision verification request for %d decisions sent to %s.\n",
                this.decisions.size(), this.getProvider().getHostAddress());
    }
}
