package com.gstuer.casc.common.attribute;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.concurrency.RequestablePolicyAttribute;
import com.gstuer.casc.common.concurrency.exception.RequestTimeoutException;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class AttributeSubscriber {
    private final ConcurrentMap<AttributeIdentifier, RequestablePolicyAttribute> attributeRequests;
    private final ConcurrentMap<AttributeIdentifier, PolicyAttribute<?>> attributes;
    private final ConcurrentMap<AttributeIdentifier, AttributeUpdater> updaters;
    private final AuthenticationClient authenticationClient;
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;

    public AttributeSubscriber(AuthenticationClient authenticationClient, BlockingQueue<AccessControlMessage<?>> messageEgress) {
        this.attributeRequests = new ConcurrentHashMap<>();
        this.attributes = new ConcurrentHashMap<>();
        this.updaters = new ConcurrentHashMap<>();
        this.authenticationClient = Objects.requireNonNull(authenticationClient);
        this.messageEgress = Objects.requireNonNull(messageEgress);
    }

    public <T> void subscribe(AttributeIdentifier identifier) {
        if (this.updaters.get(identifier) != null) {
            // Attribute already subscribed.
            return;
        }

        // Create and start updater thread for published attribute
        AttributeUpdater updater = new AttributeUpdater(identifier);
        this.updaters.put(identifier, updater);
        new Thread(updater).start();
    }

    public void unsubscribe(PolicyAttribute<?> attribute) {
        this.unsubscribe(attribute.getIdentifier());
    }

    public void unsubscribe(AttributeIdentifier identifier) {
        AttributeUpdater updater = this.updaters.get(identifier);
        if (Objects.nonNull(updater)) {
            updater.stop();
            this.updaters.remove(identifier);
        }
        this.attributeRequests.remove(identifier);
        this.attributes.remove(identifier);
    }

    public PolicyAttribute<?> get(AttributeIdentifier identifier) {
        PolicyAttribute<?> attribute = this.attributes.get(identifier);
        if (Objects.nonNull(attribute) && attribute.isValid()) {
            return attribute;
        }
        this.attributes.remove(identifier);
        return null;
    }

    public Map<AttributeIdentifier, PolicyAttribute<?>> get(Iterable<AttributeIdentifier> identifiers) {
        Map<AttributeIdentifier, PolicyAttribute<?>> attributes = new HashMap<>();
        for (AttributeIdentifier identifier : identifiers) {
            attributes.put(identifier, this.get(identifier));
        }
        return attributes;
    }

    public void processVerifiedMessage(AttributeExchangeMessage message) {
        Set<PolicyAttribute<?>> attributes = message.getPayload();
        for (PolicyAttribute<?> attribute : attributes) {
            AttributeIdentifier identifier = attribute.getIdentifier();
            if (!attribute.isValid()) {
                // An attribute value whose period of validity does not include the current instant is of no use, as
                // no AASP vouches for it at this point in time.
                System.out.printf("[AM] Attribute \"%s\" discarded: valid from %s until %s.\n",
                        identifier.getName(), attribute.getValidFrom(), attribute.getValidUntil());
                continue;
            }

            // Get attribute request for valid attribute
            RequestablePolicyAttribute request = this.attributeRequests.get(identifier);
            if (Objects.isNull(request)) {
                System.out.printf("[AM] Attribute \"%s\" discarded: no request is pending for it.\n",
                        identifier.getName());
                continue;
            }

            // Check if request was fulfilled by correct provider
            // Note: Source of message is correct, i.e., was verified prior to this check.
            if (!request.getIdentifier().getProvider().equals(message.getSource())) {
                System.out.printf("[AM] Attribute \"%s\" discarded: %s is not its provider.\n",
                        identifier.getName(), message.getSource().getHostAddress());
                continue;
            }

            // If request exists, fulfill request and remove request from request stack.
            this.attributes.put(identifier, attribute);
            request.set(attribute);
        }
    }

    private final class AttributeUpdater implements Runnable {
        private final static Duration REFRESH_THRESHOLD = Duration.ofMillis(50);
        private final static Duration SLEEP_OFFSET = Duration.ofMillis(30);
        private final static Duration RETRY_PAUSE = Duration.ofSeconds(5);
        private final AttributeIdentifier identifier;
        private boolean isRunning = true;

        private AttributeUpdater(AttributeIdentifier identifier) {
            this.identifier = Objects.requireNonNull(identifier);
        }

        @Override
        public void run() {
            while (isRunning) {
                RequestablePolicyAttribute requestableAttribute = AttributeSubscriber.this.attributeRequests.computeIfAbsent(identifier,
                        key -> new RequestablePolicyAttribute(AttributeSubscriber.this.messageEgress, AttributeSubscriber.this.authenticationClient.getSigner(), key));
                PolicyAttribute<?> attribute;
                try {
                    attribute = requestableAttribute.get();
                } catch (RequestTimeoutException timeoutException) {
                    // Remove existing attribute if not valid anymore
                    attribute = AttributeSubscriber.this.attributes.get(identifier);
                    if (Objects.nonNull(attribute) && !attribute.isValid()) {
                        AttributeSubscriber.this.attributes.remove(identifier);
                    }

                    // Attribute was not fetchable from provider within three request message periods -> Wait until retry.
                    try {
                        Thread.sleep(RETRY_PAUSE.toMillis());
                        continue;
                    } catch (InterruptedException interruptedException) {
                        this.isRunning = false;
                        break;
                    }
                }

                // Check how long attribute is valid and re-request close to end of validity
                Instant now = Instant.now();
                long millisecondsLeft = now.until(attribute.getValidUntil(), TimeUnit.MILLISECONDS.toChronoUnit());
                if (millisecondsLeft < REFRESH_THRESHOLD.toMillis()) {
                    // If less time than threshold is left, update value of attribute by requesting it from provider in next loop iteration
                    requestableAttribute.set(null);
                    continue;
                } else {
                    // If more time than threshold is left, sleep for left time minus offset
                    try {
                        Thread.sleep(millisecondsLeft - SLEEP_OFFSET.toMillis());
                        continue;
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
