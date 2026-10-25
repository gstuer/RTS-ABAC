package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.DecisionResolver;
import com.gstuer.casc.common.DecisionResolver.DecisionResolution;
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
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
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
    private final ConcurrentMap<PendingVerification, RequestableAccessVerification> requestedVerifications;
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

    /**
     * Authorizes an outgoing data frame by resolving the access decisions available for outgoing data frames. An
     * outgoing data frame is forwarded to each next hop of the resolved decision, so that one payload exchange
     * message per next hop results.
     *
     * @param packet the outgoing data frame
     * @return the payload exchange messages to be sent, which is empty if the data frame has to be dropped.
     */
    public List<PayloadExchangeMessage> authorizeOutgoing(Packet packet) {
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(packet);
        Optional<DecisionResolution> optionalResolution = DecisionResolver.getResolution(this.outgoingDecisions,
                pattern, Instant.now());

        if (optionalResolution.isEmpty() || this.isExpiring(optionalResolution.get())) {
            // No current access decision governs the data frame -> Request one from the authorization authority
            RequestableAccessDecision requestableDecision = this.requestedDecisions.computeIfAbsent(pattern,
                    key -> new RequestableAccessDecision(this.messageEgress, this.authenticationClient.getSigner(),
                            authorizationAuthority, pattern));

            // Wait until the session initialization was processed
            try {
                requestableDecision.get();
            } catch (RequestTimeoutException exception) {
                return List.of();
            }

            // Resolve again, as a session initialization may contain multiple conflicting access decisions
            optionalResolution = DecisionResolver.getResolution(this.outgoingDecisions, pattern, Instant.now());
        }

        // A granted data frame is forwarded to each next hop, a denied one is dropped
        return optionalResolution.filter(DecisionResolution::isGranting)
                .map(resolution -> resolution.nextHops().stream()
                        .map(nextHop -> new PayloadExchangeMessage(nextHop, null, packet))
                        .toList())
                .orElseGet(List::of);
    }

    /**
     * Checks whether a resolution expires within the validity offset, so that the access decisions it was derived
     * from have to be renewed before the data frames of their flow are dropped. A resolution expires as soon as the
     * first of the decisions it was derived from expires, which is the period of validity of the composite decision
     * of conflicting decisions. Renewing at that point in time rather than at the last expiry keeps a decision from
     * silently ceasing to constrain a flow, e.g. a denial that excludes a subset of a flow which a more general and
     * longer-lived decision grants.
     *
     * @param resolution the resolution of the access decisions currently available for a data frame
     * @return {@code true} if the resolution has to be renewed, {@code false} otherwise.
     */
    private boolean isExpiring(DecisionResolution resolution) {
        return resolution.validUntil().isBefore(Instant.now().plus(ACCESS_DECISION_VALIDITY_OFFSET));
    }

    /**
     * Authorizes an incoming data frame by resolving the access decisions available for incoming data frames. An
     * incoming data frame is accepted only if the resolved decision grants it and permits this PEP to receive it.
     *
     * @param message the payload exchange message carrying the incoming data frame
     * @return the data frame to be delivered, or an empty optional if it has to be dropped.
     */
    public Optional<Packet> authorizeIncoming(PayloadExchangeMessage message) {
        // Reject empty payload exchange message
        if (!message.hasPayload()) {
            return Optional.empty();
        }

        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(message.getPayload());
        Optional<DecisionResolution> optionalResolution = DecisionResolver.getResolution(this.incomingDecisions,
                pattern, Instant.now());
        if (optionalResolution.filter(DecisionResolution::isGranting)
                .filter(resolution -> resolution.isNextHop(this.authorizationScope)).isPresent()) {
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

        // A session initialization contains the access decisions of all policies matching the access request. All of
        // them are installed before the data frames awaiting the session initialization are released, as the
        // enforcement of such a frame resolves the conflicts between all decisions of the session initialization. A
        // frame released beforehand would be enforced using an incomplete set of decisions, e.g. using a granting
        // decision that a denying one of the same session initialization overrides.
        List<AccessDecision> releasingDecisions = message.getPayload().stream()
                .map(this::installDecision).flatMap(Optional::stream).toList();
        releasingDecisions.forEach(this::resolveRequests);
    }

    /**
     * Adds a single access decision of a session initialization to the local session state. A granting decision
     * governs the incoming data frames of this PEP if this PEP is one of its next hops, and the outgoing ones
     * otherwise. A decision that neither grants nor applies has an empty next hop set and may exclude a subset of a
     * flow that is granted in either direction, which is why it is added to both sets.
     *
     * @param decision the access decision of a session initialization
     * @return the access decision that releases the outgoing data frames awaiting the session initialization, or an
     * empty optional if the given decision governs the incoming data frames only.
     */
    private Optional<AccessDecision> installDecision(AccessDecision decision) {
        if (!decision.isValid()) {
            // An expired decision is not enforced, but releases the data frames awaiting it so that they are dropped
            return Optional.of(decision);
        }

        if (decision.isGranting()) {
            if (decision.isNextHop(this.authorizationScope)) {
                if (this.isVerified(decision, this.incomingVerificationAuthority)) {
                    this.incomingDecisions.add(decision);
                }
                // An incoming decision governs the data frames this PEP receives, none of which awaits a decision.
                return Optional.empty();
            }
            if (this.isVerified(decision, this.outgoingVerificationAuthority)) {
                this.outgoingDecisions.add(decision);
                return Optional.of(decision);
            }
            // The session initialization is discarded without informing the issuing PDP. The data frames awaiting it
            // are released with a denial, so that they are dropped instead of awaiting the request timeout.
            return Optional.of(denialOf(decision));
        }

        // A denying or non-applicable decision constrains both directions and permits no recipient
        if (this.isVerified(decision, this.outgoingVerificationAuthority)) {
            this.incomingDecisions.add(decision);
            this.outgoingDecisions.add(decision);
            return Optional.of(decision);
        }
        return Optional.of(denialOf(decision));
    }

    public void processMessage(AccessVerificationMessage message) {
        // Reject empty messages and messages which do not come from a configured verification authority
        if (!this.authenticationClient.verifyMessage(message) || !message.hasPayload()
                || !this.isVerificationAuthority(message.getSource())) {
            return;
        }
        this.resolveVerifications(message.getSource(), message.getPayload());
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
                && Objects.equals(verification.getNextHops(), sessionInitialization.getNextHops());
    }

    private static AccessDecision denialOf(AccessDecision decision) {
        return new AccessDecision(decision.getPattern(), AccessDecision.Action.DENY, Set.of(),
                decision.getValidUntil());
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
        PendingVerification pendingVerification = new PendingVerification(authority, decision.getPattern());
        RequestableAccessVerification requestableVerification = this.requestedVerifications
                .computeIfAbsent(pendingVerification, key -> new RequestableAccessVerification(this.messageEgress,
                        this.authenticationClient.getSigner(), key.authority(), key.pattern()));

        // Wait until the verifying PDP responded
        AccessDecision verification;
        try {
            verification = requestableVerification.get();
        } catch (RequestTimeoutException exception) {
            System.out.printf("[AC] Unverified session initialization discarded: %s unreachable.\n",
                    authority.getHostAddress());
            return false;
        } finally {
            // Discard the response, so that a subsequent session initialization for the same flow pattern is verified
            // again instead of reusing this response. A verification requested concurrently by another thread is left
            // in place, as its requester awaits a response that is yet to arrive.
            this.requestedVerifications.remove(pendingVerification, requestableVerification);
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
                    // A request issued concurrently for the same flow pattern is left in place, as its requester
                    // awaits a session initialization that is yet to arrive.
                    this.requestedDecisions.remove(entry.getKey(), entry.getValue());
                });
    }

    private void resolveVerifications(InetAddress authority, AccessDecision decision) {
        AccessRequestPattern pattern = decision.getPattern();
        requestedVerifications.entrySet().stream().parallel()
                .filter(entry -> entry.getValue().isUnavailable()
                        && entry.getKey().authority().equals(authority)
                        && entry.getKey().pattern().contains(pattern))
                .forEach(entry -> entry.getValue().set(decision));
    }

    /**
     * Identifies a pending access decision verification by the verifying PDP that it was requested from and by the
     * flow pattern that it concerns. The verifying PDP is part of the identity, so that the response of one verifying
     * PDP cannot satisfy a verification requested from another one, e.g. if the verification of incoming and of
     * outgoing session initializations is delegated to two different PDPs.
     *
     * @param authority the address of the verifying PDP the verification was requested from
     * @param pattern   the flow pattern of the session initialization to be verified
     */
    private record PendingVerification(InetAddress authority, AccessRequestPattern pattern) {
    }
}
