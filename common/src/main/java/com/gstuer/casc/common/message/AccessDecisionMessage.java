package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.AccessDecision;
import com.google.common.primitives.Bytes;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.List;

/**
 * Represents a session initialization sent by a policy decision point (PDP) to a policy enforcement point (PEP). The
 * payload contains the access decisions of all policies whose flow pattern matches the access request pattern of the
 * preceding access request, as a PEP resolves the conflicts between them itself.
 */
public class AccessDecisionMessage extends AccessControlMessage<List<AccessDecision>> {
    @Serial
    private static final long serialVersionUID = 5920009290786282627L;

    public AccessDecisionMessage(InetAddress source, InetAddress destination, DigitalSignature signature,
                                 List<AccessDecision> payload) {
        super(source, destination, signature, payload);
    }

    public AccessDecisionMessage(InetAddress destination, DigitalSignature signature, List<AccessDecision> payload) {
        super(destination, signature, payload);
    }

    public AccessDecisionMessage(InetAddress destination, DigitalSignature signature, AccessDecision payload) {
        super(destination, signature, List.of(payload));
    }

    @Override
    public AccessDecisionMessage fromSource(InetAddress source) {
        return new AccessDecisionMessage(source, this.getDestination(), this.getSignature(), this.getPayload());
    }

    @Override
    public AccessDecisionMessage sign(Signer signer) throws SignatureException, InvalidKeyException {
        DigitalSignature signature = signer.sign(getSigningData());
        return new AccessDecisionMessage(this.getSource(), this.getDestination(), signature, this.getPayload());
    }

    @Override
    public byte[] getSigningData() {
        // The decisions are signed in the order in which they are transmitted.
        byte[] signingData = new byte[0];
        for (AccessDecision decision : this.getPayload()) {
            signingData = Bytes.concat(signingData, decision.getSigningData());
        }
        return signingData;
    }
}
