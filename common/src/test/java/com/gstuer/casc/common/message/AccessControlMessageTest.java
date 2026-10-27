package com.gstuer.casc.common.message;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests the properties that every {@link AccessControlMessage access control message} has to satisfy, regardless of
 * its type.
 */
public class AccessControlMessageTest {
    /**
     * A received message states the host it was received from, which an ingress handler sets from the sender of the
     * datagram rather than trusting a transmitted value. Every message type has to adopt that host, as the
     * authentication of a message and the authorization of its content are both bound to its source: a message type
     * that discarded the host would be unverifiable and could not be served at all.
     */
    @Test
    public void testEveryMessageTypeAdoptsTheHostItWasReceivedFrom() throws Exception {
        InetAddress sender = InetAddress.getByName("127.0.0.9");

        for (AccessControlMessage<?> message : createMessageOfEveryType()) {
            AccessControlMessage<?> receivedMessage = message.fromSource(sender);

            assertEquals(sender, receivedMessage.getSource(),
                    "%s has to adopt the host it was received from.".formatted(message.getClass().getSimpleName()));
            assertEquals(message.getDestination(), receivedMessage.getDestination());
            assertEquals(message.getSignature(), receivedMessage.getSignature());
            assertNotNull(receivedMessage.getPayload());
        }
    }

    /**
     * Creates one message of every type, so that a message type added later is covered by the tests of this class as
     * soon as it is listed here.
     */
    private static List<AccessControlMessage<?>> createMessageOfEveryType() throws Exception {
        InetAddress destination = InetAddress.getByName("127.0.0.1");
        InetAddress nextHop = InetAddress.getByName("127.0.0.4");
        DigitalSignature signature = new DigitalSignature(new byte[]{1, 2, 3, 4}, "test");
        AccessRequestPattern pattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        AccessDecision decision = new AccessDecision(pattern, AccessDecision.Action.GRANT, nextHop,
                Instant.now().plusSeconds(60));
        AttributeIdentifier identifier = new AttributeIdentifier("intruded", destination);
        PolicyAttribute<?> attribute = new LongAttribute(identifier, Instant.now(), Duration.ofSeconds(5), 0L);
        EthernetPacket packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.IPV4)
                .paddingAtBuild(true)
                .build();

        return List.of(
                new AccessRequestMessage(destination, signature, pattern),
                new AccessDecisionMessage(destination, signature, List.of(decision)),
                new AccessVerificationRequestMessage(destination, signature, List.of(decision)),
                new AccessVerificationMessage(destination, signature,
                        List.of(new AccessDecisionVerdict(decision, true, Instant.now().plusSeconds(60)))),
                new AttributeExchangeRequestMessage(destination, signature, Set.of(identifier)),
                new AttributeExchangeMessage(destination, signature, Set.of(attribute)),
                new PayloadExchangeMessage(destination, signature, packet),
                new KeyExchangeRequestMessage(destination, signature, NoOperationAuthenticator.ALGORITHM_IDENTIFIER),
                new KeyExchangeMessage(destination, signature,
                        new EncodedKey(NoOperationAuthenticator.ALGORITHM_IDENTIFIER, new byte[]{1, 2})));
    }
}
