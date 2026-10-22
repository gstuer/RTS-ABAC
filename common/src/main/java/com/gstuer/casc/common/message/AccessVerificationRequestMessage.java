package com.gstuer.casc.common.message;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.io.Serial;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * Represents an access decision verification request sent by a policy enforcement point (PEP) to a policy decision
 * point (PDP) to verify a previously received session initialization. The payload is the flow pattern of the access
 * decision to be verified.
 * <p>
 * In contrast to an {@link AccessRequestMessage access request}, a verification request does not initialize a session,
 * i.e. the addressed PDP responds to the requesting PEP only and does not send session initializations to the next hop
 * PEPs of the matching access decisions.
 */
public class AccessVerificationRequestMessage extends AccessControlMessage<AccessRequestPattern> {
    @Serial
    private static final long serialVersionUID = 1471925960381048399L;

    public AccessVerificationRequestMessage(InetAddress source, InetAddress destination, DigitalSignature signature,
                                            AccessRequestPattern payload) {
        super(source, destination, signature, payload);
    }

    public AccessVerificationRequestMessage(InetAddress destination, DigitalSignature signature, AccessRequestPattern payload) {
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
        return this.getPayload().getSigningData();
    }
}
