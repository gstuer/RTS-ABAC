package com.gstuer.casc.common.message;

import com.google.common.primitives.Bytes;
import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.List;

/**
 * Represents an access decision verification request sent by a policy enforcement point (PEP) to a policy decision
 * point (PDP) to verify a previously received session initialization. The payload contains the access decisions to be
 * verified, i.e. the decisions of the session initialization that the PEP intends to enforce.
 * <p>
 * The decisions are submitted rather than their flow pattern, as a session initialization contains one or multiple
 * decisions whose conflicts the PEP resolves itself: a response that contained the decisions of the addressed PDP
 * instead of a verdict per submitted decision would have to be mapped onto the submitted ones before either of them
 * could be enforced. Submitting all decisions of a session initialization in one request moreover keeps the
 * verification at one round trip per session initialization and verifying PDP.
 * <p>
 * In contrast to an {@link AccessRequestMessage access request}, a verification request does not initialize a session,
 * i.e. the addressed PDP responds to the requesting PEP only and does not send session initializations to the next hop
 * PEPs of the matching access decisions.
 */
public class AccessVerificationRequestMessage extends AccessControlMessage<List<AccessDecision>> {
    @Serial
    private static final long serialVersionUID = 1471925960381048399L;

    public AccessVerificationRequestMessage(InetAddress source, InetAddress destination, DigitalSignature signature,
                                            List<AccessDecision> payload) {
        super(source, destination, signature, payload);
    }

    public AccessVerificationRequestMessage(InetAddress destination, DigitalSignature signature,
                                            List<AccessDecision> payload) {
        super(destination, signature, payload);
    }

    @Override
    public AccessVerificationRequestMessage fromSource(InetAddress source) {
        return new AccessVerificationRequestMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AccessVerificationRequestMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AccessVerificationRequestMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        // The decisions to be verified are signed in the order in which they are transmitted.
        byte[] signingData = new byte[0];
        for (AccessDecision decision : this.getPayload()) {
            signingData = Bytes.concat(signingData, decision.getSigningData());
        }
        return signingData;
    }
}
