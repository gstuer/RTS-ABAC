package com.gstuer.casc.aasp;

import com.gstuer.casc.aasp.AttributeConfiguration.AttributeDefinition;
import com.gstuer.casc.aasp.source.AttributeSource;
import com.gstuer.casc.aasp.source.AttributeSourceFactory;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.aasp.attribute.AttributeFactory;
import com.gstuer.casc.aasp.attribute.AttributePublisher;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;

import java.net.InetAddress;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

/**
 * Serves the attributes of an attribute administration and storage point (AASP), i.e. it publishes the configured
 * attributes and answers the attribute requests of the PDPs that evaluate policies against them.
 */
public class AttributeController {
    private final AuthenticationClient authenticationClient;
    private final AttributePublisher attributePublisher;

    /**
     * Constructs a new {@link AttributeController attribute controller} and publishes the configured attributes.
     *
     * @param egressQueue             the queue of outbound access control messages
     * @param authenticationAuthority the address of the authentication authority
     * @param authenticator           the authenticator used to sign and verify messages
     * @param provider                the address at which the PDPs reach this AASP, which identifies its attributes
     * @param configuration           the configuration of the attributes to be published
     */
    public AttributeController(BlockingQueue<AccessControlMessage<?>> egressQueue,
                               InetAddress authenticationAuthority, Authenticator<?, ?> authenticator,
                               InetAddress provider, AttributeConfiguration configuration) {
        this.authenticationClient = new AuthenticationClient(authenticationAuthority, authenticator,
                Objects.requireNonNull(egressQueue));
        this.attributePublisher = new AttributePublisher(this.authenticationClient, egressQueue);
        this.publishAttributes(provider, configuration);
    }

    /**
     * Handles an incoming access control message. An AASP answers the attribute requests of the PDPs and takes part
     * in the key exchange required to authenticate them; it neither evaluates policies nor enforces decisions.
     *
     * @param accessControlMessage the received access control message
     */
    public void handleRequest(AccessControlMessage<?> accessControlMessage) {
        if (accessControlMessage instanceof AttributeExchangeRequestMessage message) {
            // Verify signature
            if (!this.authenticationClient.verifyMessage(message) || !message.hasPayload()) {
                return;
            }
            this.attributePublisher.processVerifiedMessage(message);
            System.out.printf("[AASP] Attributes %s requested by %s.\n", message.getPayload().stream()
                    .map(AttributeIdentifier::getName).toList(), message.getSource().getHostAddress());
        } else if (accessControlMessage instanceof KeyExchangeMessage message) {
            this.authenticationClient.processMessage(message);
        } else if (accessControlMessage instanceof KeyExchangeRequestMessage message) {
            this.authenticationClient.processMessage(message);
        } else {
            System.out.println("[AASP] Unknown message type.");
        }
    }

    /**
     * Publishes the configured attributes, so that each of them is refreshed from its source once per period of
     * validity and is served to the requesting PDPs.
     *
     * @param provider      the address at which the PDPs reach this AASP
     * @param configuration the configuration of the attributes to be published
     * @throws IllegalArgumentException if an attribute states an unknown type or an unknown kind of source, or if
     *                                  its source cannot be read at startup
     */
    private void publishAttributes(InetAddress provider, AttributeConfiguration configuration) {
        for (AttributeDefinition definition : configuration.attributes()) {
            AttributeSource source = AttributeSourceFactory.createBySourceType(definition.source())
                    .orElseThrow(() -> new IllegalArgumentException("Attribute \"" + definition.name()
                            + "\" states an unknown kind of source: " + definition.source()));
            AttributeIdentifier identifier = new AttributeIdentifier(definition.name(), provider);
            PolicyAttribute<?> attribute = AttributeFactory.createByTypeIdentifier(definition.type(), identifier,
                            definition.validity(), source)
                    .orElseThrow(() -> new IllegalArgumentException("Attribute \"" + definition.name()
                            + "\" states an unknown type: " + definition.type()));

            this.attributePublisher.publish(attribute);
            System.out.printf("[AASP] Publishing attribute \"%s\" of type %s, valid for %s, initial value: %s\n",
                    definition.name(), definition.type(), definition.validity(), attribute.getValue());
        }
    }
}
