package com.gstuer.casc.common.concurrency;

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

    private static RequestableAccessVerification createVerification(BlockingQueue<AccessControlMessage<?>> egress,
                                                                    InetAddress provider, AccessRequestPattern pattern) {
        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        return new RequestableAccessVerification(egress, authenticator, provider, pattern);
    }

    @Test
    public void testConstructedRequestMessageTargetsVerificationProvider() throws UnknownHostException {
        // Test data
        BlockingQueue<AccessControlMessage<?>> egress = new LinkedBlockingQueue<>();
        InetAddress provider = InetAddress.getByName("127.0.0.3");
        AccessRequestPattern pattern = createPattern();
        RequestableAccessVerification verification = createVerification(egress, provider, pattern);

        // Execution
        AccessControlMessage<?> message = verification.constructRequestMessage();

        // Assertions
        assertInstanceOf(AccessVerificationRequestMessage.class, message);
        assertEquals(provider, message.getDestination());
        assertEquals(pattern, message.getPayload());
        assertTrue(message.hasSignature());
    }

    @Test
    public void testSendRequestMessageQueuesVerificationRequest() throws UnknownHostException {
        // Test data
        BlockingQueue<AccessControlMessage<?>> egress = new LinkedBlockingQueue<>();
        InetAddress provider = InetAddress.getByName("127.0.0.3");
        AccessRequestPattern pattern = createPattern();
        RequestableAccessVerification verification = createVerification(egress, provider, pattern);

        // Execution
        verification.sendRequestMessage();

        // Assertions
        assertEquals(1, egress.size());
        assertInstanceOf(AccessVerificationRequestMessage.class, egress.poll());
        assertTrue(verification.isRequestPending());
        assertTrue(verification.isUnavailable());
    }

    @Test
    public void testPatternIsRetained() throws UnknownHostException {
        // Test data
        AccessRequestPattern pattern = createPattern();

        // Execution
        RequestableAccessVerification verification = createVerification(new LinkedBlockingQueue<>(),
                InetAddress.getByName("127.0.0.3"), pattern);

        // Assertion
        assertEquals(pattern, verification.getPattern());
    }
}
