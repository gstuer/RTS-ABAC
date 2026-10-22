package com.gstuer.casc.pdp;

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
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    public void testVerificationRequestIsAnsweredToRequesterOnly() throws Exception {
        // Execution
        this.controller.handleRequest(new AccessVerificationRequestMessage(this.requester,
                this.authenticationAuthority, null, policyPattern()).sign(remoteAuthenticator()));

        // Assertions
        //// A verification request yields exactly one message, which is addressed to the requesting PEP. In contrast
        //// to an access request, it initializes no session at the next hop PEP of the decision.
        List<AccessControlMessage<?>> responses = List.copyOf(this.egress);
        assertEquals(1, responses.size());
        AccessControlMessage<?> response = responses.get(0);
        assertInstanceOf(AccessVerificationMessage.class, response);
        assertEquals(this.requester, response.getDestination());
        assertTrue(((AccessVerificationMessage) response).getPayload().isGranting());
        assertEquals(policyPattern(), ((AccessVerificationMessage) response).getPayload().getPattern());
    }

    @Test
    public void testAccessRequestStillInitializesSessionAtNextHop() throws Exception {
        // Execution
        this.controller.handleRequest(new AccessRequestMessage(this.requester, this.authenticationAuthority,
                null, policyPattern()).sign(remoteAuthenticator()));

        // Assertions
        //// An access request yields a session initialization for the next hop PEP and one for the requesting PEP
        List<AccessControlMessage<?>> responses = List.copyOf(this.egress);
        assertEquals(2, responses.size());
        assertTrue(responses.stream().allMatch(message -> message instanceof AccessDecisionMessage));
        assertEquals(InetAddress.getByName("192.168.0.61"), responses.get(0).getDestination());
        assertEquals(this.requester, responses.get(1).getDestination());
    }

    @Test
    public void testVerificationRequestForUnknownFlowIsDenied() throws Exception {
        // Test data
        AccessRequestPattern unknownPattern = new EthernetPattern(POLICY_DESTINATION_MAC, POLICY_SOURCE_MAC,
                EtherType.ARP);

        // Execution
        this.controller.handleRequest(new AccessVerificationRequestMessage(this.requester,
                this.authenticationAuthority, null, unknownPattern).sign(remoteAuthenticator()));

        // Assertions
        List<AccessControlMessage<?>> responses = List.copyOf(this.egress);
        assertEquals(1, responses.size());
        AccessVerificationMessage response = assertInstanceOf(AccessVerificationMessage.class, responses.get(0));
        assertEquals(this.requester, response.getDestination());
        assertTrue(response.getPayload().isDenying());
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
