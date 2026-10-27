package com.gstuer.casc.aasp.attribute;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.AttributeSubscriber;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.cryptography.HmacAuthenticator;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.serialization.JsonProcessor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the attribute exchange between the {@link AttributePublisher publisher} of an AASP and the
 * {@link AttributeSubscriber subscriber} of a PDP. The messages are serialized and deserialized as the ingress and
 * egress handlers of the two components do, and the source of a message is set from the host it was received from,
 * so that the test covers the exchange as it happens between two hosts rather than the two components in isolation.
 */
public class AttributeExchangeTest {
    private static final long TIMEOUT_SECONDS = 5;

    private InetAddress aasp;
    private InetAddress pdp;
    private AttributeIdentifier identifier;
    private BlockingQueue<AccessControlMessage<?>> publisherEgress;
    private BlockingQueue<AccessControlMessage<?>> subscriberEgress;
    private AttributePublisher publisher;
    private AttributeSubscriber subscriber;

    @BeforeEach
    public void setUp() throws Exception {
        this.aasp = InetAddress.getByName("127.0.0.100");
        this.pdp = InetAddress.getByName("127.0.0.64");
        this.identifier = new AttributeIdentifier("intruded", this.aasp);

        NoOperationAuthenticator publisherAuthenticator = createAuthenticator();
        NoOperationAuthenticator subscriberAuthenticator = createAuthenticator();
        this.publisherEgress = new LinkedBlockingQueue<>();
        this.subscriberEgress = new LinkedBlockingQueue<>();
        AuthenticationClient publisherClient = new AuthenticationClient(this.aasp, publisherAuthenticator,
                this.publisherEgress);
        AuthenticationClient subscriberClient = new AuthenticationClient(this.pdp, subscriberAuthenticator,
                this.subscriberEgress);

        // Seed the verifiers of both sides, so that no key exchange is required during the exchange
        seedVerifier(publisherClient, this.pdp, subscriberAuthenticator);
        seedVerifier(subscriberClient, this.aasp, publisherAuthenticator);
        this.publisherEgress.clear();
        this.subscriberEgress.clear();

        this.publisher = new AttributePublisher(publisherClient, this.publisherEgress);
        this.subscriber = new AttributeSubscriber(subscriberClient, this.subscriberEgress);
    }

    /**
     * A PDP fetches the value of a published attribute from the AASP that publishes it: the subscriber requests the
     * attribute, the publisher answers with its current value and period of validity, and the subscriber holds the
     * value afterwards. The attribute is published from a source, as an AASP publishes it.
     */
    @Test
    public void testPublishedAttributeIsFetchedByASubscriber() throws Exception {
        this.publisher.publish(LongAttribute.createFromData(this.identifier, Duration.ofSeconds(5), () -> "1"));

        this.subscriber.subscribe(this.identifier);
        this.relayAttributeExchange();

        PolicyAttribute<?> attribute = this.subscriber.get(this.identifier);
        assertNotNull(attribute, "The subscriber has to hold the value of the requested attribute.");
        assertEquals(1L, attribute.getValue());
        assertEquals(this.identifier, attribute.getIdentifier());
        assertTrue(attribute.isValid());
    }

    /**
     * An attribute that no AASP publishes is not answered with a value, so that a PDP treats the policies requiring
     * it as non-applicable instead of evaluating them against a value nobody vouches for.
     */
    @Test
    public void testUnpublishedAttributeIsNotServed() throws Exception {
        AttributeIdentifier unpublished = new AttributeIdentifier("unpublished", this.aasp);

        this.subscriber.subscribe(unpublished);
        this.relayAttributeExchange();

        assertNull(this.subscriber.get(unpublished));
    }

    /**
     * The publisher answers a request with the authenticator the AASP is configured with, which is an HMAC
     * authenticator on the testbed rather than the no-operation authenticator of the tests above. An answer that
     * states no attribute, because none of the requested ones is published, has to be signed as well.
     */
    @Test
    public void testPublisherAnswersWithTheConfiguredAuthenticator() throws Exception {
        BlockingQueue<AccessControlMessage<?>> egress = new LinkedBlockingQueue<>();
        HmacAuthenticator authenticator = new HmacAuthenticator();
        authenticator.initializeKeyPair();
        AuthenticationClient client = new AuthenticationClient(this.aasp, authenticator, egress);
        AttributePublisher hmacPublisher = new AttributePublisher(client, egress);
        hmacPublisher.publish(LongAttribute.createFromData(this.identifier, Duration.ofSeconds(5), () -> "1"));
        egress.clear();

        // A request for a published attribute is answered
        hmacPublisher.processVerifiedMessage(new AttributeExchangeRequestMessage(this.pdp, this.aasp, null,
                Set.of(this.identifier)));
        AccessControlMessage<?> response = egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeMessage.class, response);
        assertEquals(1, ((AttributeExchangeMessage) response).getPayload().size());

        // A request for an attribute this AASP does not publish is answered as well, stating no attribute
        hmacPublisher.processVerifiedMessage(new AttributeExchangeRequestMessage(this.pdp, this.aasp, null,
                Set.of(new AttributeIdentifier("unpublished", this.aasp))));
        AccessControlMessage<?> emptyResponse = egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeMessage.class, emptyResponse);
        assertTrue(((AttributeExchangeMessage) emptyResponse).getPayload().isEmpty());
    }

    /**
     * Relays the attribute request of the subscriber to the publisher and the response of the publisher back to the
     * subscriber, serializing and deserializing both messages and setting their source from the host they were
     * received from, as the ingress and egress handlers of the two components do.
     */
    private void relayAttributeExchange() throws Exception {
        AccessControlMessage<?> request = this.subscriberEgress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeRequestMessage.class, request,
                "The subscriber has to request the attribute from its provider.");
        assertEquals(this.aasp, request.getDestination());
        this.publisher.processVerifiedMessage((AttributeExchangeRequestMessage) transmit(request, this.pdp));

        AccessControlMessage<?> response = this.publisherEgress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeMessage.class, response, "The publisher has to answer the request.");
        assertEquals(this.pdp, response.getDestination());
        this.subscriber.processVerifiedMessage((AttributeExchangeMessage) transmit(response, this.aasp));
    }

    /**
     * Transmits a message as the egress and ingress handlers do, i.e. serializes it, deserializes it, and sets its
     * source from the host it was received from.
     *
     * @param message the message to be transmitted
     * @param sender  the host the message is received from
     * @return the received message.
     */
    private static AccessControlMessage<?> transmit(AccessControlMessage<?> message, InetAddress sender)
            throws Exception {
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessControlMessage<?> receivedMessage = jsonProcessor.deserialize(jsonProcessor.serialize(message),
                AccessControlMessage.class);
        return receivedMessage.fromSource(sender);
    }

    private static void seedVerifier(AuthenticationClient client, InetAddress host,
                                     NoOperationAuthenticator authenticator) throws Exception {
        EncodedKey encodedKey = new EncodedKey(NoOperationAuthenticator.ALGORITHM_IDENTIFIER,
                authenticator.getVerificationKey().getEncoded());
        client.processMessage(new KeyExchangeMessage(host, host, null, encodedKey).sign(authenticator));
    }

    private static NoOperationAuthenticator createAuthenticator() {
        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        return authenticator;
    }
}
