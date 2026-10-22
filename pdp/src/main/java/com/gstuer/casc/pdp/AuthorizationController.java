package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessPolicy;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.attribute.AttributeSubscriber;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.StaticResultPredicate;
import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.message.AccessVerificationMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class AuthorizationController {
    private final AuthenticationClient authenticationClient;
    private final BlockingQueue<AccessControlMessage<?>> egressQueue;
    private final AttributeSubscriber attributeSubscriber;
    private final EvaluationManager evaluationManager;

    public AuthorizationController(BlockingQueue<AccessControlMessage<?>> egressQueue,
                                   InetAddress authenticationAuthority, Authenticator<?, ?> authenticator) {
        this.egressQueue = egressQueue;
        this.authenticationClient = new AuthenticationClient(authenticationAuthority, authenticator, this.egressQueue);
        this.attributeSubscriber = new AttributeSubscriber(this.authenticationClient, this.egressQueue);
        this.evaluationManager = new EvaluationManager(attributeSubscriber);

        // TODO Remove static rules
        /* MAC Addresses
         * - Blueberry  00:e0:4c:68:02:40
         * - Blackberry 00:e0:4c:68:02:69
         * - Huckleberry 2c:cf:67:a8:50:a6
         * - Lingonberry 2c:cf:67:a8:51:24
         * - Gooseberry 2c:cf:67:a8:51:7e
         * - Strawberry 2c:cf:67:a8:51:87
         * - Cranberry 2c:cf:67:a8:51:a8
         */

        // Rules for office benchmarking
        EthernetPattern lingonToGoosePattern = new EthernetPattern(MacAddress.getByName("2c:cf:67:a8:51:24"),
                MacAddress.getByName("2c:cf:67:a8:51:7e"), EtherType.IPV4);
        EthernetPattern gooseToLingonPattern = new EthernetPattern(MacAddress.getByName("2c:cf:67:a8:51:7e"),
                MacAddress.getByName("2c:cf:67:a8:51:24"), EtherType.IPV4);
        PolicyPredicate predicate = new StaticResultPredicate(true, Duration.ofSeconds(5));
        try {
            AccessPolicy lingonToGoosePolicy = new AccessPolicy(lingonToGoosePattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), predicate);
            AccessPolicy gooseToLingonPolicy = new AccessPolicy(gooseToLingonPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), predicate);
            this.evaluationManager.addPolicy(lingonToGoosePolicy);
            this.evaluationManager.addPolicy(gooseToLingonPolicy);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }

        /*
        // Rules for lab evaluation - Subsystem 2 - Siemens-only (6MU85 + 7SX85 + 6MD84)
        // TODO only let goose/sv pass + deactivate sv bypass
        PolicyPredicate predicate = new StaticResultPredicate(true, Duration.ofSeconds(15));
        try {
            // Siemens Devices Subsys. MAC Addresses
            // MU b4:b1:5a:1e:7d:d9
            // IED b4:b1:5a:1e:87:81
            // IO unknown

            // Policy for MU to IED via SV
            EthernetPattern muToIedPattern = new EthernetPattern(MacAddress.getByName("b4:b1:5a:1e:7d:d9"),
                    MacAddress.getByName("01:0c:cd:01:00:04"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            AccessPolicy muToIedPolicy = new AccessPolicy(muToIedPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), predicate);
            this.evaluationManager.addPolicy(muToIedPolicy);

            // Policy for IED to IO-Box via GOOSE
            EthernetPattern iedToIoPattern = new EthernetPattern(MacAddress.getByName("b4:b1:5a:1e:87:81"),
                    MacAddress.getByName("01:0c:cd:01:00:03"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            AccessPolicy iedToIoPolicy = new AccessPolicy(iedToIoPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), predicate);
            this.evaluationManager.addPolicy(iedToIoPolicy);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
        */

        /*
        // Rules for lab evaluation - Subsystem 2 - GE MU320 + GE F60 + Siemens 6MD84
        // TODO only let goose/sv pass + deactivate sv bypass
        PolicyPredicate predicate = new StaticResultPredicate(true, Duration.ofSeconds(15));
        try {
            // MU320 f8:02:78:10:62:a5
            // IED dc:37:52:0a:0a:1d
            // IO unknown

            // Policy for MU to IED via SV
            EthernetPattern muToIedPattern = new EthernetPattern(MacAddress.getByName("f8:02:78:10:62:a5"),
                    MacAddress.getByName("01:0c:cd:01:00:00"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            AccessPolicy muToIedPolicy = new AccessPolicy(muToIedPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), predicate);
            this.evaluationManager.addPolicy(muToIedPolicy);

            // Policy for IED to IO-Box via GOOSE
            EthernetPattern iedToIoPattern = new EthernetPattern(MacAddress.getByName("dc:37:52:0a:0a:1d"),
                    MacAddress.getByName("01:0c:cd:01:02:02"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            AccessPolicy iedToIoPolicy = new AccessPolicy(iedToIoPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), predicate);
            this.evaluationManager.addPolicy(iedToIoPolicy);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
        */

        // Rules for lab evaluation - Subsystem 2 - SEL401 + Hitachi Rel670 + Siemens 6MD84
        // TODO only let goose/sv pass + deactivate sv bypass
        /*
        PolicyPredicate predicate = new StaticResultPredicate(true, Duration.ofSeconds(15));
        try {
            // MU 00:30:a7:30:b4:5b
            // IED REL670 00:02:a3:e2:9d:c1
            // IO unknown

            // Policy for MU to IED via SV
            EthernetPattern muToIedPattern = new EthernetPattern(MacAddress.getByName("00:30:a7:30:b4:5b"),
                    MacAddress.getByName("01:0c:cd:01:00:13"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            EthernetPattern muToIedPattern2 = new EthernetPattern(MacAddress.getByName("00:30:a7:30:b4:5c"),
                    MacAddress.getByName("01:0c:cd:04:02:01"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            AccessPolicy muToIedPolicy = new AccessPolicy(muToIedPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), predicate);
            AccessPolicy muToIedPolicy2 = new AccessPolicy(muToIedPattern2, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), predicate);
            this.evaluationManager.addPolicy(muToIedPolicy);
            this.evaluationManager.addPolicy(muToIedPolicy2);

            // Policy for IED to IO-Box via GOOSE
            EthernetPattern iedToIoPattern = new EthernetPattern(MacAddress.getByName("00:02:a3:e2:9d:c1"),
                    MacAddress.getByName("01:0c:cd:01:01:02"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
            AccessPolicy iedToIoPolicy = new AccessPolicy(iedToIoPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), predicate);
            this.evaluationManager.addPolicy(iedToIoPolicy);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
         */
    }

    public void handleRequest(AccessControlMessage<?> accessControlMessage) {
        long arrivalTime = System.nanoTime();
        // Identify type of message
        if (accessControlMessage instanceof KeyExchangeMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationClient.processMessage(message);
        } else if (accessControlMessage instanceof KeyExchangeRequestMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationClient.processMessage(message);
        } else if (accessControlMessage instanceof AttributeExchangeMessage message) {
            // Verify message signature
            if (!this.authenticationClient.verifyMessage(message)) {
                return;
            }
            // Forward message to attribute subscriber for processing
            this.attributeSubscriber.processVerifiedMessage(message);
        } else if (accessControlMessage instanceof AccessRequestMessage message) {
            // Verify signature
            if (!this.authenticationClient.verifyMessage(message)) {
                return;
            }

            // Get matching decisions for message
            AccessRequestPattern pattern = message.getPayload();
            AccessDecision decision = this.evaluationManager.getDecision(pattern);

            // Send decision to next hop if granted
            if (decision.isGranting()) {
                AccessDecisionMessage decisionMessage = new AccessDecisionMessage(decision.getNextHop(), null, decision);
                Optional<AccessControlMessage<?>> optionalSignedMessage = authenticationClient.signMessage(decisionMessage);
                if (optionalSignedMessage.isPresent()) {
                    this.egressQueue.offer(optionalSignedMessage.get());
                } else {
                    System.out.println("[PDP] Signing failed.");
                    return;
                }
            }

            // Send decision to requester
            AccessDecisionMessage decisionMessage = new AccessDecisionMessage(message.getSource(), null, decision);
            Optional<AccessControlMessage<?>> optionalSignedMessage = authenticationClient.signMessage(decisionMessage);
            if (optionalSignedMessage.isPresent()) {
                this.egressQueue.offer(optionalSignedMessage.get());
                if (decision.isGranting()) {
                    System.out.printf("[PDP] Grant: %s -> %s. (took %d µs)\n", message.getSource(), decision.getNextHop(), TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - arrivalTime));
                } else {
                    System.out.printf("[PDP] Deny: %s. (took %d µs)\n", message.getSource(), TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - arrivalTime));
                }
            } else {
                System.out.println("[PDP] Signing failed.");
                return;
            }
        } else if (accessControlMessage instanceof AccessVerificationRequestMessage message) {
            // Verify signature
            if (!this.authenticationClient.verifyMessage(message)) {
                return;
            }

            // Get matching decision for the flow pattern whose session initialization is verified
            AccessRequestPattern pattern = message.getPayload();
            AccessDecision decision = this.evaluationManager.getDecision(pattern);

            // Send decision to the requester only, i.e. without initializing sessions at the next hop PEPs
            AccessVerificationMessage verificationMessage = new AccessVerificationMessage(message.getSource(), null, decision);
            Optional<AccessControlMessage<?>> optionalSignedMessage = authenticationClient.signMessage(verificationMessage);
            if (optionalSignedMessage.isEmpty()) {
                System.out.println("[PDP] Signing failed.");
                return;
            }
            this.egressQueue.offer(optionalSignedMessage.get());
            System.out.printf("[PDP] Verify %s: %s. (took %d µs)\n", decision.isGranting() ? "grant" : "deny",
                    message.getSource(), TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - arrivalTime));
        } else {
            System.out.println("[PDP] Unknown message type.");
        }
    }
}
