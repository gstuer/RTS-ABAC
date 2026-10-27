package com.gstuer.casc.common.concurrency;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RequestableAccessVerificationTest {
    private static AccessRequestPattern createPattern() {
        return new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
    }

    private static List<AccessDecision> createDecisions() {
        return List.of(new AccessDecision(createPattern(), AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60)));
    }

    private static RequestableAccessVerification createVerification(BlockingQueue<AccessControlMessage<?>> egress,
                                                                    InetAddress provider,
                                                                    List<AccessDecision> decisions) {
        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        return new RequestableAccessVerification(egress, authenticator, provider, decisions);
    }

    @Test
    public void testConstructedRequestMessageTargetsVerificationProvider() throws UnknownHostException {
        // Test data
        BlockingQueue<AccessControlMessage<?>> egress = new LinkedBlockingQueue<>();
        InetAddress provider = InetAddress.getByName("127.0.0.3");
        List<AccessDecision> decisions = createDecisions();
        RequestableAccessVerification verification = createVerification(egress, provider, decisions);

        // Execution
        AccessControlMessage<?> message = verification.constructRequestMessage();

        // Assertions
        assertInstanceOf(AccessVerificationRequestMessage.class, message);
        assertEquals(provider, message.getDestination());
        assertEquals(decisions, message.getPayload());
        assertTrue(message.hasSignature());
    }

    @Test
    public void testSendRequestMessageQueuesVerificationRequest() throws UnknownHostException {
        // Test data
        BlockingQueue<AccessControlMessage<?>> egress = new LinkedBlockingQueue<>();
        InetAddress provider = InetAddress.getByName("127.0.0.3");
        RequestableAccessVerification verification = createVerification(egress, provider, createDecisions());

        // Execution
        verification.sendRequestMessage();

        // Assertions
        assertEquals(1, egress.size());
        assertInstanceOf(AccessVerificationRequestMessage.class, egress.poll());
        assertTrue(verification.isRequestPending());
        assertTrue(verification.isUnavailable());
    }

    /**
     * The access decisions to be verified are retained by the resource, as a PEP assigns the verdicts of the
     * response to the decisions it submitted.
     */
    @Test
    public void testDecisionsAreRetained() throws UnknownHostException {
        // Test data
        List<AccessDecision> decisions = createDecisions();

        // Execution
        RequestableAccessVerification verification = createVerification(new LinkedBlockingQueue<>(),
                InetAddress.getByName("127.0.0.3"), decisions);

        // Assertion
        assertEquals(decisions, verification.getDecisions());
    }
}
