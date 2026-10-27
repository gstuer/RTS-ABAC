package com.gstuer.casc.aasp.attribute;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Publishes the {@link PolicyAttribute attributes} that an attribute administration and storage point (AASP)
 * administers, and serves them to the PDPs that evaluate policies against them.
 * <p>
 * The publisher realises the attribute evaluation function of the RTS-ABAC approach: it refreshes the value of each
 * published attribute from the source of that attribute once per period of validity, and it vouches for a value for
 * that period only. A PDP that evaluates a policy against such a value bounds the period of validity of the
 * resulting access decision by it, which is why the period of an attribute corresponds to the rate at which its
 * value changes.
 */
public class AttributePublisher {
    private final ConcurrentMap<AttributeIdentifier, PolicyAttribute<?>> attributes;
    private final ConcurrentMap<AttributeIdentifier, AttributeUpdater> updaters;
    private final AuthenticationClient authenticationClient;
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;

    public AttributePublisher(AuthenticationClient authenticationClient, BlockingQueue<AccessControlMessage<?>> messageEgress) {
        this.attributes = new ConcurrentHashMap<>();
        this.updaters = new ConcurrentHashMap<>();
        this.authenticationClient = Objects.requireNonNull(authenticationClient);
        this.messageEgress = Objects.requireNonNull(messageEgress);
    }

    public <T> void publish(PolicyAttribute<T> attribute) {
        if (!attribute.hasValueSupplier()) {
            throw new IllegalArgumentException("Cannot publish attribute without value supplier.");
        }
        this.attributes.put(attribute.getIdentifier(), attribute);

        // Create and start updater thread for published attribute
        AttributeUpdater updater = new AttributeUpdater(attribute);
        this.updaters.put(attribute.getIdentifier(), updater);
        new Thread(updater).start();
    }

    public void unpublish(PolicyAttribute<?> attribute) {
        this.unpublish(attribute.getIdentifier());
    }

    public void unpublish(AttributeIdentifier identifier) {
        this.attributes.remove(identifier);
        AttributeUpdater updater = this.updaters.get(identifier);
        if (Objects.nonNull(updater)) {
            updater.stop();
            this.updaters.remove(identifier);
        }
    }

    public PolicyAttribute<?> get(AttributeIdentifier identifier) {
        return this.attributes.get(identifier);
    }

    public void processVerifiedMessage(AttributeExchangeRequestMessage message) {
        Set<AttributeIdentifier> identifiers = message.getPayload();
        Set<PolicyAttribute<?>> attributes = identifiers.parallelStream()
                .map(this::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        AttributeExchangeMessage exchangeMessage = new AttributeExchangeMessage(message.getSource(), null, attributes);
        Optional<AccessControlMessage<?>> signedMessage = this.authenticationClient.signMessage(exchangeMessage);
        if (signedMessage.isEmpty()) {
            System.err.printf("[AASP] Attribute resolution for %s could not be signed.\n",
                    message.getSource().getHostAddress());
            return;
        }
        this.messageEgress.offer(signedMessage.get());
        System.out.printf("[AASP] %d of %d requested attributes served to %s.\n", attributes.size(),
                identifiers.size(), message.getSource().getHostAddress());
    }

    private static final class AttributeUpdater implements Runnable {
        private final static Duration REFRESH_THRESHOLD = Duration.ofMillis(10);
        private final static Duration SLEEP_OFFSET = Duration.ofMillis(5);
        private final static Duration RETRY_PAUSE = Duration.ofMillis(500);
        private final PolicyAttribute<?> attribute;
        private boolean isRunning = true;

        private AttributeUpdater(PolicyAttribute<?> attribute) {
            this.attribute = Objects.requireNonNull(attribute);
        }

        @Override
        public void run() {
            while (isRunning) {
                Instant now = Instant.now();
                long millisecondsLeft = now.until(attribute.getValidUntil(), TimeUnit.MILLISECONDS.toChronoUnit());
                if (millisecondsLeft < REFRESH_THRESHOLD.toMillis()) {
                    // If less time than threshold is left, update value of attribute
                    try {
                        attribute.update();
                    } catch (RuntimeException exception) {
                        // A value that is momentarily unavailable, e.g. because its source cannot be read, must not
                        // end the refresh of the attribute: the attribute expires instead, so that no PDP evaluates
                        // a policy against a value this AASP no longer vouches for, and the next refresh retries.
                        System.err.printf("[AASP] Refresh of attribute \"%s\" failed: %s\n",
                                attribute.getIdentifier().getName(), exception.getMessage());
                        try {
                            Thread.sleep(RETRY_PAUSE.toMillis());
                        } catch (InterruptedException interruptedException) {
                            this.isRunning = false;
                            break;
                        }
                    }
                } else {
                    // If more time than threshold is left, sleep for left time minus offset
                    try {
                        Thread.sleep(millisecondsLeft - SLEEP_OFFSET.toMillis());
                    } catch (InterruptedException exception) {
                        this.isRunning = false;
                        break;
                    }
                }
            }
        }

        /**
         * Stops this updater safely, i.e., without interrupting it but by stopping the execution after the next sleep
         * period.
         */
        public void stop() {
            this.isRunning = false;
        }
    }
}
