package com.gstuer.casc.common.message;

import com.google.common.primitives.Bytes;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.List;

/**
 * Represents the response of a policy decision point (PDP) to an
 * {@link AccessVerificationRequestMessage access decision verification request}. The payload contains one
 * {@link AccessDecisionVerdict verdict} per submitted access decision, which states whether the responding PDP holds
 * the same access decision for the flow pattern of the submitted one.
 * <p>
 * A verification response is distinct from an {@link AccessDecisionMessage session initialization} so that a policy
 * enforcement point (PEP) can tell the two apart: a session initialization is subject to verification, whereas a
 * verification response is the evidence against which a session initialization is verified and therefore must not
 * trigger a verification itself.
 */
public class AccessVerificationMessage extends AccessControlMessage<List<AccessDecisionVerdict>> {
    @Serial
    private static final long serialVersionUID = -6355206518932765124L;

    public AccessVerificationMessage(InetAddress source, InetAddress destination, DigitalSignature signature,
                                     List<AccessDecisionVerdict> payload) {
        super(source, destination, signature, payload);
    }

    public AccessVerificationMessage(InetAddress destination, DigitalSignature signature,
                                     List<AccessDecisionVerdict> payload) {
        super(destination, signature, payload);
    }

    @Override
    public AccessVerificationMessage fromSource(InetAddress source) {
        return new AccessVerificationMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AccessVerificationMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AccessVerificationMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        // The verdicts are signed in the order in which they are transmitted.
        byte[] signingData = new byte[0];
        for (AccessDecisionVerdict verdict : this.getPayload()) {
            signingData = Bytes.concat(signingData, verdict.getSigningData());
        }
        return signingData;
    }
}
