package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.message.AccessVerificationMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthorizationControllerTest {
    // The policy set hardcoded in the controller grants this flow and names 192.168.0.61 as its next hop.
    private static final MacAddress POLICY_SOURCE_MAC = MacAddress.getByName("2c:cf:67:a8:51:24");
    private static final MacAddress POLICY_DESTINATION_MAC = MacAddress.getByName("2c:cf:67:a8:51:7e");

    private BlockingQueue<AccessControlMessage<?>> egress;
    private AuthorizationController controller;
    private InetAddress requester;
    private InetAddress authenticationAuthority;

    @BeforeEach
    public void setUp() throws Exception {
        this.egress = new LinkedBlockingQueue<>();
        this.requester = InetAddress.getByName("127.0.0.5");
        this.authenticationAuthority = InetAddress.getByName("127.0.0.1");
        this.controller = new AuthorizationController(this.egress, this.authenticationAuthority,
                new NoOperationAuthenticator());

        // Seed the verifier for the requester through the key exchange the controller handles itself
        NoOperationAuthenticator remote = remoteAuthenticator();
        EncodedKey encodedKey = new EncodedKey(NoOperationAuthenticator.ALGORITHM_IDENTIFIER,
                remote.getVerificationKey().getEncoded());
        this.controller.handleRequest(new KeyExchangeMessage(this.requester, this.authenticationAuthority,
                null, encodedKey).sign(remote));
        this.egress.clear();
    }

    /**
     * A verification request yields exactly one message, which is addressed to the requesting PEP and contains one
     * verdict per submitted access decision. In contrast to an access request, it initializes no session at the next
     * hop PEP of the decision, so that the verification does not become observable outside the requesting PEP.
     */
    @Test
    public void testVerificationRequestIsAnsweredToRequesterOnly() throws Exception {
        // Test data
        AccessDecision decision = policyDecision();

        // Execution
        this.controller.handleRequest(new AccessVerificationRequestMessage(this.requester,
                this.authenticationAuthority, null, List.of(decision)).sign(remoteAuthenticator()));

        // Assertions
        List<AccessControlMessage<?>> responses = List.copyOf(this.egress);
        assertEquals(1, responses.size());
        AccessVerificationMessage response = assertInstanceOf(AccessVerificationMessage.class, responses.get(0));
        assertEquals(this.requester, response.getDestination());
        assertEquals(1, response.getPayload().size());
        assertEquals(decision, response.getPayload().get(0).getDecision());
        assertTrue(response.getPayload().get(0).isVerified());
    }

    /**
     * A PDP confirms an access decision only if it holds the same decision for the same flow pattern. A deviating
     * action, a deviating next hop, and a flow pattern that no own policy matches are therefore rejected, as each of
     * them indicates a fault, a compromise, or an attribute value that changed between the two evaluations.
     */
    @Test
    public void testDeviatingDecisionsAreNotConfirmed() throws Exception {
        // Test data
        AccessRequestPattern unknownPattern = new EthernetPattern(POLICY_DESTINATION_MAC, POLICY_SOURCE_MAC,
                EtherType.ARP);
        Instant validUntil = Instant.now().plusSeconds(60);
        List<AccessDecision> decisions = List.of(
                policyDecision(),
                new AccessDecision(policyPattern(), AccessDecision.Action.DENY, Set.of(), validUntil),
                new AccessDecision(policyPattern(), AccessDecision.Action.GRANT,
                        InetAddress.getByName("192.168.0.99"), validUntil),
                new AccessDecision(unknownPattern, AccessDecision.Action.GRANT,
                        InetAddress.getByName("192.168.0.61"), validUntil));

        // Execution
        this.controller.handleRequest(new AccessVerificationRequestMessage(this.requester,
                this.authenticationAuthority, null, decisions).sign(remoteAuthenticator()));

        // Assertions
        AccessVerificationMessage response = assertInstanceOf(AccessVerificationMessage.class,
                List.copyOf(this.egress).get(0));
        assertEquals(4, response.getPayload().size(), "One verdict per submitted access decision is returned.");
        assertTrue(response.getPayload().get(0).isVerified(), "The decision of the own policy is confirmed.");
        assertFalse(response.getPayload().get(1).isVerified(), "A deviating action is not confirmed.");
        assertFalse(response.getPayload().get(2).isVerified(), "A deviating next hop is not confirmed.");
        assertFalse(response.getPayload().get(3).isVerified(), "An unmatched flow pattern is not confirmed.");
    }

    /**
     * A verdict never outlives the access decision it concerns, as the issuing PDP does not vouch for its decision
     * beyond its own period of validity. The exact period of a verdict is the minimum of the two decisions, which
     * {@link EvaluationManagerTest} pins down for a policy set whose validity the test controls.
     */
    @Test
    public void testVerdictDoesNotOutliveTheVerifiedDecision() throws Exception {
        // Test data
        AccessDecision decision = policyDecision();

        // Execution
        this.controller.handleRequest(new AccessVerificationRequestMessage(this.requester,
                this.authenticationAuthority, null, List.of(decision)).sign(remoteAuthenticator()));

        // Assertion
        AccessVerificationMessage response = assertInstanceOf(AccessVerificationMessage.class,
                List.copyOf(this.egress).get(0));
        assertFalse(response.getPayload().get(0).getValidUntil().isAfter(decision.getValidUntil()));
    }

    private static AccessDecision policyDecision() throws UnknownHostException {
        // The access decision that the policy set hardcoded in the controller yields for the flow it grants.
        return new AccessDecision(policyPattern(), AccessDecision.Action.GRANT,
                InetAddress.getByName("192.168.0.61"), Instant.now().plusSeconds(60));
    }

    private static AccessRequestPattern policyPattern() {
        return new EthernetPattern(POLICY_SOURCE_MAC, POLICY_DESTINATION_MAC, EtherType.IPV4);
    }

    private static NoOperationAuthenticator remoteAuthenticator() {
        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        return authenticator;
    }
}
