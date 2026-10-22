package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.concurrency.RequestableAccessDecision;
import com.gstuer.casc.common.concurrency.RequestableAccessVerification;
import com.gstuer.casc.common.concurrency.exception.RequestTimeoutException;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessVerificationMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.PatternFactory;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedSet;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;

public class AuthorizationManager {
    private final TemporalAmount ACCESS_DECISION_VALIDITY_OFFSET = Duration.ofMillis(100);

    private final InetAddress authorizationAuthority;
    private final InetAddress authorizationScope;
    private final InetAddress incomingVerificationAuthority;
    private final InetAddress outgoingVerificationAuthority;
    private final AuthenticationClient authenticationClient;
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;
    private final ConcurrentMap<AccessRequestPattern, RequestableAccessDecision> requestedDecisions;
    private final ConcurrentMap<AccessRequestPattern, RequestableAccessVerification> requestedVerifications;
    private final SortedSet<AccessDecision> outgoingDecisions;
    private final SortedSet<AccessDecision> incomingDecisions;

    public AuthorizationManager(InetAddress authorizationAuthority,
                                InetAddress authorizationScope,
                                AuthenticationClient authenticationClient,
                                BlockingQueue<AccessControlMessage<?>> messageEgress) {
        this(authorizationAuthority, authorizationScope, null, null, authenticationClient, messageEgress);
    }

    /**
     * Constructs a new {@link AuthorizationManager authorization manager}.
     *
     * @param authorizationAuthority        the address of the PDP that issues the session initializations
     * @param authorizationScope            the address of this PEP, used to tell incoming from outgoing decisions
     * @param incomingVerificationAuthority the address of the PDP against which session initializations for incoming
     *                                      traffic are verified, or {@code null} to accept them unverified
     * @param outgoingVerificationAuthority the address of the PDP against which session initializations for outgoing
     *                                      traffic are verified, or {@code null} to accept them unverified
     * @param authenticationClient          the authentication client used to sign and verify messages
     * @param messageEgress                 the queue of outbound access control messages
     */
    public AuthorizationManager(InetAddress authorizationAuthority,
                                InetAddress authorizationScope,
                                InetAddress incomingVerificationAuthority,
                                InetAddress outgoingVerificationAuthority,
                                AuthenticationClient authenticationClient,
                                BlockingQueue<AccessControlMessage<?>> messageEgress) {
        this.authorizationAuthority = Objects.requireNonNull(authorizationAuthority);
        this.authorizationScope = Objects.requireNonNull(authorizationScope);
        this.incomingVerificationAuthority = incomingVerificationAuthority;
        this.outgoingVerificationAuthority = outgoingVerificationAuthority;
        this.authenticationClient = Objects.requireNonNull(authenticationClient);
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.requestedDecisions = new ConcurrentHashMap<>();
        this.requestedVerifications = new ConcurrentHashMap<>();
        this.outgoingDecisions = new ConcurrentSkipListSet<>();
        this.incomingDecisions = new ConcurrentSkipListSet<>();
    }

    public Optional<PayloadExchangeMessage> authorizeOutgoing(Packet packet) {
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(packet);
        Optional<AccessDecision> optionalDecision = this.outgoingDecisions.stream().parallel()
                .filter(decision -> pattern.contains(decision.getPattern())
                        && decision.isValid(ACCESS_DECISION_VALIDITY_OFFSET))
                .findFirst();

        if (optionalDecision.isPresent()) {
            AccessDecision decision = optionalDecision.get();
            if (decision.isGranting()) {
                // Access Granted -> Construct unsigned payload exchange message
                PayloadExchangeMessage message = new PayloadExchangeMessage(decision.getNextHop(), null, packet);
                return Optional.of(message);
            }
            // Access Denied -> Reject packet
            return Optional.empty();
        } else {
            // Request new decision from authorization authority
            RequestableAccessDecision requestableDecision = this.requestedDecisions.computeIfAbsent(pattern,
                    key -> new RequestableAccessDecision(this.messageEgress, this.authenticationClient.getSigner(),
                            authorizationAuthority, pattern));

            // Wait until decision is available
            AccessDecision decision;
            try {
                decision = requestableDecision.get();
            } catch (RequestTimeoutException exception) {
                return Optional.empty();
            }

            // If decision was positive return unsigned payload exchange message, return empty optional otherwise
            PayloadExchangeMessage message = null;
            if (decision.isGranting() && decision.isValid()) {
                message = new PayloadExchangeMessage(decision.getNextHop(), null, packet);
            }
            return Optional.ofNullable(message);
        }
    }

    public Optional<Packet> authorizeIncoming(PayloadExchangeMessage message) {
        // Reject empty payload exchange message
        if (!message.hasPayload()) {
            return Optional.empty();
        }

        // Check if pattern for message exists in incoming rules
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(message.getPayload());
        Optional<AccessDecision> optionalDecision = this.incomingDecisions.stream().parallel()
                .filter(decision -> pattern.contains(decision.getPattern())
                        && decision.isGranting() && decision.isValid())
                .findFirst();

        // Return payload if decision is present, return empty optional otherwise
        if (optionalDecision.isPresent()) {
            return Optional.of(message.getPayload());
        }
        return Optional.empty();
    }

    public void processMessage(AccessDecisionMessage message) {
        // Reject empty messages and messages which do not come from a policy decision point (authorization authority)
        if (!this.authenticationClient.verifyMessage(message) || !message.hasPayload()
                || !this.authorizationAuthority.equals(message.getSource())) {
            return;
        }

        // Add decision to either the outgoing or incoming rules
        AccessDecision decision = message.getPayload();
        if (authorizationScope.equals(decision.getNextHop())) {
            // If nextHop equals own scope, decision is still valid, & is granted -> Add to incoming rules
            if (decision.isGranting() && decision.isValid()
                    && this.isVerified(decision, this.incomingVerificationAuthority)) {
                // Only save granted decisions as incoming rules
                this.incomingDecisions.add(decision);
            }
        } else if (decision.isValid()) {
            // If nextHop does not equal own scope, add decision to outgoing rules and resolve possible waiting packets
            if (this.isVerified(decision, this.outgoingVerificationAuthority)) {
                this.outgoingDecisions.add(decision);
                this.resolveRequests(decision);
            } else {
                // The session initialization is discarded without informing the issuing PDP. The data frames awaiting
                // it are resolved with a denial, so that they are dropped instead of awaiting the request timeout.
                this.resolveRequests(denialOf(decision));
            }
        } else {
            // If nextHop does not equal own scope and decision is not valid (anymore), only resolve waiting packets
            this.resolveRequests(decision);
        }
    }

    public void processMessage(AccessVerificationMessage message) {
        // Reject empty messages and messages which do not come from a configured verification authority
        if (!this.authenticationClient.verifyMessage(message) || !message.hasPayload()
                || !this.isVerificationAuthority(message.getSource())) {
            return;
        }
        this.resolveVerifications(message.getPayload());
    }

    /**
     * Checks whether the {@link AccessDecision access decision} of a verifying PDP authorizes the data frame flow of a
     * session initialization, i.e. whether it covers the flow pattern of the session initialization, is still valid,
     * and takes the same action for the same next hop.
     *
     * @param verification          the access decision received from the verifying PDP
     * @param sessionInitialization the access decision received as a session initialization
     * @return {@code true} if the verification authorizes the flow of the session initialization, {@code false}
     * otherwise.
     */
    static boolean authorizes(AccessDecision verification, AccessDecision sessionInitialization) {
        if (Objects.isNull(verification) || Objects.isNull(sessionInitialization)) {
            return false;
        }

        // The verifying PDP may answer with a decision whose flow pattern is more general than the requested one, as a
        // less specific policy also covers the flow of the session initialization.
        if (!sessionInitialization.getPattern().contains(verification.getPattern())) {
            return false;
        }

        // A deviating action or next hop indicates a fault, a compromise, or an attribute value that changed between
        // the two evaluations. In either case the session initialization does not become effective.
        return verification.isValid() && verification.getAction() == sessionInitialization.getAction()
                && Objects.equals(verification.getNextHop(), sessionInitialization.getNextHop());
    }

    private static AccessDecision denialOf(AccessDecision decision) {
        return new AccessDecision(decision.getPattern(), AccessDecision.Action.DENY, null, decision.getValidUntil());
    }

    /**
     * Checks whether an {@link AccessDecision access decision} received as a session initialization is authorized by
     * the PDP at the given address. If no address is given, i.e. if the server-aided access decision verification is
     * disabled for the direction in question, the decision is accepted without verification.
     *
     * @param decision  the access decision of the session initialization to be verified
     * @param authority the address of the verifying PDP, or {@code null} if verification is disabled
     * @return {@code true} if the decision may become effective, {@code false} otherwise.
     */
    private boolean isVerified(AccessDecision decision, InetAddress authority) {
        if (Objects.isNull(authority)) {
            return true;
        }

        // Request the access decision that the verifying PDP holds for the flow pattern of the session initialization
        AccessRequestPattern pattern = decision.getPattern();
        RequestableAccessVerification requestableVerification = this.requestedVerifications.computeIfAbsent(pattern,
                key -> new RequestableAccessVerification(this.messageEgress, this.authenticationClient.getSigner(),
                        authority, key));

        // Wait until the verifying PDP responded
        AccessDecision verification;
        try {
            verification = requestableVerification.get();
        } catch (RequestTimeoutException exception) {
            System.out.printf("[AC] Unverified session initialization discarded: %s unreachable.\n",
                    authority.getHostAddress());
            return false;
        } finally {
            this.requestedVerifications.remove(pattern);
        }

        boolean verified = authorizes(verification, decision);
        if (!verified) {
            System.out.printf("[AC] Unverifiable session initialization discarded: %s does not authorize the flow.\n",
                    authority.getHostAddress());
        }
        return verified;
    }

    private boolean isVerificationAuthority(InetAddress address) {
        return Objects.nonNull(address) && (address.equals(this.incomingVerificationAuthority)
                || address.equals(this.outgoingVerificationAuthority));
    }

    private void resolveRequests(AccessDecision decision) {
        AccessRequestPattern pattern = decision.getPattern();
        requestedDecisions.entrySet().stream().parallel()
                .filter(entry -> entry.getValue().isUnavailable() && entry.getKey().contains(pattern))
                .forEach(entry -> {
                    entry.getValue().set(decision);
                    this.requestedDecisions.remove(entry.getKey());
                });
    }

    private void resolveVerifications(AccessDecision decision) {
        AccessRequestPattern pattern = decision.getPattern();
        requestedVerifications.entrySet().stream().parallel()
                .filter(entry -> entry.getValue().isUnavailable() && entry.getKey().contains(pattern))
                .forEach(entry -> entry.getValue().set(decision));
    }
}
