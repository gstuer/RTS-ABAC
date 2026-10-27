package com.gstuer.casc.pdp.attribute;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;
import com.gstuer.casc.common.serialization.JsonProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests how a PDP fetches the attributes its policies require from the AASPs that publish them. The responses are
 * serialized and deserialized as the egress and ingress handlers of the two components do, and their source is set
 * from the host they were received from, so that the test covers the exchange between two hosts.
 */
public class AttributeSubscriberTest {
    private static final long TIMEOUT_SECONDS = 5;

    private InetAddress aasp;
    private InetAddress pdp;
    private AttributeIdentifier identifier;
    private BlockingQueue<AccessControlMessage<?>> egress;
    private AttributeSubscriber subscriber;

    @BeforeEach
    public void setUp() throws Exception {
        this.aasp = InetAddress.getByName("127.0.0.100");
        this.pdp = InetAddress.getByName("127.0.0.64");
        this.identifier = new AttributeIdentifier("intruded", this.aasp);
        this.egress = new LinkedBlockingQueue<>();

        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        this.subscriber = new AttributeSubscriber(new AuthenticationClient(this.pdp, authenticator, this.egress),
                this.egress);
    }

    @AfterEach
    public void tearDown() {
        // The subscriber requests a subscribed attribute in a thread of its own, which outlives the test otherwise.
        this.subscriber.unsubscribe(this.identifier);
    }

    /**
     * A PDP requests a subscribed attribute from the AASP that publishes it, which the identifier of the attribute
     * names. The attributes are therefore fetched from one or multiple AASPs without the PDP being configured with
     * their addresses.
     */
    @Test
    public void testSubscribedAttributeIsRequestedFromItsProvider() throws Exception {
        this.subscriber.subscribe(this.identifier);

        AccessControlMessage<?> request = this.egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        AttributeExchangeRequestMessage attributeRequest = assertInstanceOf(AttributeExchangeRequestMessage.class,
                request);
        assertEquals(this.aasp, attributeRequest.getDestination());
        assertEquals(Set.of(this.identifier), attributeRequest.getPayload());
    }

    /**
     * The value an AASP answers with is held by the PDP, so that its policies are evaluated against it without
     * fetching an attribute on the critical path of an access request.
     */
    @Test
    public void testReceivedValueIsHeld() throws Exception {
        this.awaitRequest();

        this.subscriber.processVerifiedMessage(this.resolution(this.aasp, this.attribute(1L,
                Duration.ofSeconds(5))));

        PolicyAttribute<?> attribute = this.subscriber.get(this.identifier);
        assertNotNull(attribute, "The subscriber has to hold the value of the requested attribute.");
        assertEquals(1L, attribute.getValue());
        assertEquals(this.identifier, attribute.getIdentifier());
    }

    /**
     * A value whose period of validity has elapsed is discarded, as no AASP vouches for it any more. The policies
     * requiring the attribute are then not applicable until a current value arrives.
     */
    @Test
    public void testExpiredValueIsDiscarded() throws Exception {
        this.awaitRequest();

        this.subscriber.processVerifiedMessage(this.resolution(this.aasp,
                new LongAttribute(this.identifier, Instant.now().minusSeconds(10), Duration.ofSeconds(5), 1L)));

        assertNull(this.subscriber.get(this.identifier));
    }

    /**
     * A value answered by a host other than the provider named by the identifier is discarded, so that a host which
     * does not administer an attribute cannot determine the system state a PDP evaluates its policies against.
     */
    @Test
    public void testValueFromAnotherHostIsDiscarded() throws Exception {
        this.awaitRequest();

        this.subscriber.processVerifiedMessage(this.resolution(InetAddress.getByName("127.0.0.66"),
                this.attribute(1L, Duration.ofSeconds(5))));

        assertNull(this.subscriber.get(this.identifier));
    }

    /**
     * Subscribes the attribute and awaits the resulting attribute request, so that a response can be answered to a
     * request that is actually pending.
     */
    private void awaitRequest() throws InterruptedException {
        this.subscriber.subscribe(this.identifier);
        assertInstanceOf(AttributeExchangeRequestMessage.class, this.egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    }

    /**
     * Builds the response of an AASP as the PDP receives it, i.e. serialized, deserialized, and attributed to the
     * host it was received from.
     *
     * @param sender    the host the response is received from
     * @param attribute the attribute stated by the response
     * @return the received response.
     */
    private AttributeExchangeMessage resolution(InetAddress sender, PolicyAttribute<?> attribute) throws Exception {
        AttributeExchangeMessage response = new AttributeExchangeMessage(this.pdp, null, Set.of(attribute));
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessControlMessage<?> receivedMessage = jsonProcessor.deserialize(jsonProcessor.serialize(response),
                AccessControlMessage.class);
        return (AttributeExchangeMessage) receivedMessage.fromSource(sender);
    }

    private PolicyAttribute<?> attribute(long value, Duration validity) {
        return new LongAttribute(this.identifier, Instant.now(), validity, value);
    }
}
