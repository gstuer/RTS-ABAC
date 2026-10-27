package com.gstuer.casc.aasp.attribute;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.cryptography.HmacAuthenticator;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;
import com.gstuer.casc.common.serialization.JsonProcessor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests how an AASP answers the attribute requests of a PDP, i.e. the resolution of the attributes it publishes. The
 * response is serialized and deserialized as the egress and ingress handlers of the two components do, so that the
 * test covers what a PDP receives rather than what the publisher constructs.
 */
public class AttributeResolutionTest {
    private static final long TIMEOUT_SECONDS = 5;

    private InetAddress aasp;
    private InetAddress pdp;
    private AttributeIdentifier identifier;
    private BlockingQueue<AccessControlMessage<?>> egress;
    private AttributePublisher publisher;

    @BeforeEach
    public void setUp() throws Exception {
        this.aasp = InetAddress.getByName("127.0.0.100");
        this.pdp = InetAddress.getByName("127.0.0.64");
        this.identifier = new AttributeIdentifier("intruded", this.aasp);
        this.egress = new LinkedBlockingQueue<>();

        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        this.publisher = new AttributePublisher(new AuthenticationClient(this.aasp, authenticator, this.egress),
                this.egress);
    }

    /**
     * An AASP answers an attribute request with the current value of the requested attribute and with the period of
     * validity it vouches for. Both have to survive the wire format, as the PDP bounds the period of validity of
     * every access decision it derives from the value by that period.
     */
    @Test
    public void testPublishedAttributeIsServedWithItsPeriodOfValidity() throws Exception {
        PolicyAttribute<?> attribute = LongAttribute.createFromData(this.identifier, Duration.ofSeconds(5),
                () -> "1");
        this.publisher.publish(attribute);
        this.egress.clear();

        AttributeExchangeMessage response = this.requestAttributes(this.identifier);

        assertEquals(this.pdp, response.getDestination());
        assertEquals(1, response.getPayload().size());
        PolicyAttribute<?> servedAttribute = response.getPayload().iterator().next();
        assertEquals(this.identifier, servedAttribute.getIdentifier());
        assertEquals(1L, servedAttribute.getValue());
        assertEquals(Duration.ofSeconds(5), servedAttribute.getValidityDuration());
        assertTrue(servedAttribute.isValid());
        assertArrayEquals(attribute.getSigningData(), servedAttribute.getSigningData(),
                "The signature of the AASP covers the served value and its period of validity.");
    }

    /**
     * An attribute that this AASP does not publish is not answered with a value, so that a PDP treats the policies
     * requiring it as non-applicable instead of evaluating them against a value nobody vouches for.
     */
    @Test
    public void testUnpublishedAttributeIsNotServed() throws Exception {
        AttributeExchangeMessage response = this.requestAttributes(new AttributeIdentifier("unpublished",
                this.aasp));

        assertTrue(response.getPayload().isEmpty());
    }

    /**
     * The response is signed with the authenticator the AASP is configured with, which is an HMAC authenticator on
     * the testbed. A response that states no attribute is signed as well.
     */
    @Test
    public void testPublisherAnswersWithTheConfiguredAuthenticator() throws Exception {
        HmacAuthenticator authenticator = new HmacAuthenticator();
        authenticator.initializeKeyPair();
        AttributePublisher hmacPublisher = new AttributePublisher(
                new AuthenticationClient(this.aasp, authenticator, this.egress), this.egress);
        hmacPublisher.publish(LongAttribute.createFromData(this.identifier, Duration.ofSeconds(5), () -> "1"));
        this.egress.clear();

        hmacPublisher.processVerifiedMessage(this.request(this.identifier));
        AccessControlMessage<?> response = this.egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeMessage.class, response);
        assertTrue(response.hasSignature());

        hmacPublisher.processVerifiedMessage(this.request(new AttributeIdentifier("unpublished", this.aasp)));
        AccessControlMessage<?> emptyResponse = this.egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeMessage.class, emptyResponse);
        assertTrue(emptyResponse.hasSignature(), "A response without an attribute is signed as well.");
    }

    /**
     * Requests the given attributes from the publisher and returns the response as a PDP receives it, i.e. after it
     * was serialized, deserialized, and attributed to the host it was received from.
     */
    private AttributeExchangeMessage requestAttributes(AttributeIdentifier... identifiers) throws Exception {
        this.publisher.processVerifiedMessage(this.request(identifiers));
        AccessControlMessage<?> response = this.egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        assertInstanceOf(AttributeExchangeMessage.class, response, "The publisher has to answer the request.");

        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessControlMessage<?> receivedMessage = jsonProcessor.deserialize(jsonProcessor.serialize(response),
                AccessControlMessage.class);
        return (AttributeExchangeMessage) receivedMessage.fromSource(this.aasp);
    }

    private AttributeExchangeRequestMessage request(AttributeIdentifier... identifiers) {
        return new AttributeExchangeRequestMessage(this.pdp, this.aasp, null, Set.of(identifiers));
    }
}
