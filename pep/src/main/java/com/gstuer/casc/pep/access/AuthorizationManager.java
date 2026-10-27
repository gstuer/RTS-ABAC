package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.DecisionCache;
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
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

public class AuthorizationManager {
    private static final int MAX_REQUESTED_FLOWS = 1024;

    private final TemporalAmount ACCESS_DECISION_VALIDITY_OFFSET = Duration.ofMillis(100);
    private final TemporalAmount UNREACHABLE_AUTHORITY_BACKOFF = Duration.ofSeconds(1);

    private final InetAddress authorizationAuthority;
    private final InetAddress authorizationScope;
    private final InetAddress incomingVerificationAuthority;
    private final InetAddress outgoingVerificationAuthority;
    private final AuthenticationClient authenticationClient;
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;
    private final ConcurrentMap<AccessRequestPattern, RequestableAccessDecision> requestedDecisions;
    private final ConcurrentMap<PendingVerification, RequestableAccessVerification> requestedVerifications;
    private final ConcurrentMap<RetainedVerdict, AccessDecisionVerdict> retainedVerdicts;
    private final ConcurrentMap<AccessRequestPattern, Instant> suppressedRequests;
    private final ConcurrentMap<AccessRequestPattern, Instant> requestedFlows;
    private final DecisionCache outgoingDecisions;
    private final DecisionCache incomingDecisions;

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
     * @param incomingVerificationAuthority the address of the PDP against which access decisions for incoming
     *                                      traffic are verified, or {@code null} to accept them unverified
     * @param outgoingVerificationAuthority the address of the PDP against which access decisions for outgoing
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
        this.retainedVerdicts = new ConcurrentHashMap<>();
        this.suppressedRequests = new ConcurrentHashMap<>();
        this.requestedFlows = new ConcurrentHashMap<>();
        this.outgoingDecisions = new DecisionCache();
        this.incomingDecisions = new DecisionCache();
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
        Optional<DecisionResolution> optionalResolution = this.outgoingDecisions.getResolution(pattern,
                Instant.now());

        if (this.isRequestRequired(pattern, optionalResolution)) {
            // No current access decision was requested for the flow -> Request one from the authorization authority
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
            optionalResolution = this.outgoingDecisions.getResolution(pattern, Instant.now());
            this.retainRequestedFlow(pattern, optionalResolution);
        }

        // A granted data frame is forwarded to each next hop, a denied one is dropped
        return optionalResolution.filter(DecisionResolution::isGranting)
                .map(resolution -> resolution.nextHops().stream()
                        .map(nextHop -> new PayloadExchangeMessage(nextHop, null, packet))
                        .toList())
                .orElseGet(List::of);
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
        Optional<DecisionResolution> optionalResolution = this.incomingDecisions.getResolution(pattern,
                Instant.now());
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

        // An expired access decision is not enforced, but releases the data frames awaiting it so that they are
        // dropped instead of awaiting the request timeout.
        List<AccessDecision> decisions = message.getPayload();
        decisions.stream().filter(decision -> !decision.isValid()).forEach(this::releaseRequests);

        // A session initialization contains the access decisions of all policies matching the access request, all of
        // which are installed before the data frames awaiting the session initialization are released: the
        // enforcement of such a frame resolves the conflicts between all decisions of the session initialization, so
        // that a frame released beforehand would be enforced using an incomplete set of decisions.
        List<AccessDecision> validDecisions = decisions.stream().filter(AccessDecision::isValid).toList();
        this.installDecisions(validDecisions);

        // A decision that governs the outgoing data frames releases the frames awaiting it, whether or not it became
        // effective: a released frame resolves the decisions available afterwards and is dropped if none governs it.
        validDecisions.stream()
                .filter(decision -> this.getDirections(decision).contains(Direction.OUTGOING))
                .forEach(this::releaseRequests);

        System.out.printf("[AC] Session initialization of %d decisions processed: %d incoming, %d outgoing"
                        + " decisions cached.\n", decisions.size(), this.incomingDecisions.getDecisionCount(),
                this.outgoingDecisions.getDecisionCount());
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
     * Installs the access decisions of a session initialization in the local session state. Each decision is written
     * into the decision cache of the direction it governs, which requires the green light of the PDP that verifies
     * that direction: a verifying PDP vouches for the decisions written into the cache of its own direction, so that
     * a decision governing both directions requires the green light of both verifying PDPs. A direction for which no
     * verifying PDP is configured is written without verification.
     *
     * @param decisions the valid access decisions of a session initialization
     */
    private void installDecisions(List<AccessDecision> decisions) {
        // The decisions are verified in one request per verifying PDP, so that one round trip per PDP suffices for a
        // whole session initialization.
        Map<InetAddress, Map<AccessDecision, AccessDecisionVerdict>> verdicts = new HashMap<>();
        this.getDecisionsByAuthority(decisions).forEach((authority, authorityDecisions) ->
                verdicts.put(authority, this.getVerdicts(authority, List.copyOf(authorityDecisions))));

        for (AccessDecision decision : decisions) {
            for (Direction direction : this.getDirections(decision)) {
                InetAddress authority = this.getVerificationAuthority(direction);
                if (Objects.isNull(authority)) {
                    // The server-aided verification is disabled for this direction
                    this.getDecisions(direction).addDecision(decision);
                    continue;
                }

                AccessDecisionVerdict verdict = verdicts.getOrDefault(authority, Map.of()).get(decision);
                if (Objects.nonNull(verdict) && verdict.isVerified()) {
                    this.getDecisions(direction).addDecision(decision);
                    continue;
                }

                // The session initialization is discarded without informing the issuing PDP. The outcome is retained
                // for the period of validity of the verdict, so that it is disclosed neither by a repeated access
                // request nor by a repeated verification request.
                System.out.printf("[AC] Unverifiable access decision discarded: %s does not confirm a %s decision.\n",
                        authority.getHostAddress(), decision.getAction());
                if (direction == Direction.OUTGOING) {
                    this.suppressRequests(decision.getPattern(), Objects.isNull(verdict)
                            ? Instant.now().plus(UNREACHABLE_AUTHORITY_BACKOFF) : verdict.getValidUntil());
                }
            }
        }
    }

    /**
     * Gets the access decisions of a session initialization that each verifying PDP has to vouch for, i.e. those
     * written into the decision cache of the direction that the PDP verifies.
     *
     * @param decisions the valid access decisions of a session initialization
     * @return the access decisions to be verified, by the address of the verifying PDP.
     */
    private Map<InetAddress, Set<AccessDecision>> getDecisionsByAuthority(List<AccessDecision> decisions) {
        Map<InetAddress, Set<AccessDecision>> decisionsByAuthority = new HashMap<>();
        for (AccessDecision decision : decisions) {
            for (Direction direction : this.getDirections(decision)) {
                InetAddress authority = this.getVerificationAuthority(direction);
                if (Objects.nonNull(authority)) {
                    decisionsByAuthority.computeIfAbsent(authority, key -> new LinkedHashSet<>()).add(decision);
                }
            }
        }
        return decisionsByAuthority;
    }

    /**
     * Gets the verdicts of a verifying PDP for the given access decisions. A verdict that is still valid is retained
     * rather than requested again, so that the verification of a renewed session initialization costs no round trip
     * as long as the verdicts of its decisions hold.
     *
     * @param authority the address of the verifying PDP
     * @param decisions the access decisions to be verified
     * @return the verdict per access decision, which contains no verdict for a decision the PDP did not answer for.
     */
    private Map<AccessDecision, AccessDecisionVerdict> getVerdicts(InetAddress authority,
                                                                   List<AccessDecision> decisions) {
        Map<AccessDecision, AccessDecisionVerdict> verdicts = new HashMap<>();
        List<AccessDecision> unverifiedDecisions = new ArrayList<>();
        for (AccessDecision decision : decisions) {
            AccessDecisionVerdict verdict = this.retainedVerdicts
                    .get(new RetainedVerdict(authority, decision.getAuthorization()));
            if (Objects.nonNull(verdict) && verdict.isValid()) {
                verdicts.put(decision, verdict);
            } else {
                unverifiedDecisions.add(decision);
            }
        }
        if (unverifiedDecisions.isEmpty()) {
            return verdicts;
        }

        // Request the verdicts of the verifying PDP for the decisions without a retained verdict
        PendingVerification pendingVerification = new PendingVerification(authority, List.copyOf(unverifiedDecisions));
        RequestableAccessVerification requestableVerification = this.requestedVerifications
                .computeIfAbsent(pendingVerification, key -> new RequestableAccessVerification(this.messageEgress,
                        this.authenticationClient.getSigner(), key.authority(), key.decisions()));

        // Wait until the verifying PDP responded
        List<AccessDecisionVerdict> response;
        try {
            response = requestableVerification.get();
        } catch (RequestTimeoutException exception) {
            System.out.printf("[AC] Unverified session initialization discarded: %s unreachable.\n",
                    authority.getHostAddress());
            return verdicts;
        } finally {
            this.requestedVerifications.remove(pendingVerification, requestableVerification);
        }

        // Retain the verdicts of the decisions that were verified, so that they need no further round trip
        for (AccessDecisionVerdict verdict : response) {
            if (!unverifiedDecisions.contains(verdict.getDecision())) {
                continue;
            }
            this.retainedVerdicts.put(new RetainedVerdict(authority,
                    verdict.getDecision().getAuthorization()), verdict);
            verdicts.put(verdict.getDecision(), verdict);
        }
        return verdicts;
    }

    /**
     * Checks whether an access request is to be performed for a data frame. An access request is performed once per
     * data frame flow rather than once per data frame, i.e. for the first data frame of a flow and again once the
     * access decisions of that flow expire.
     * <p>
     * The access request of a flow is performed even if a more general access decision of another flow matches the
     * data frame. Such a decision does not state the decisions of the policies that match this flow more
     * specifically, so that enforcing it would enforce a policy set that depends on the flow which happened to be
     * requested first: a denial that excludes this flow from a more generally granted one would never reach this
     * PEP.
     *
     * @param pattern    the access request pattern of the data frame
     * @param resolution the resolution of the access decisions currently available for the data frame
     * @return {@code true} if an access request is to be performed, {@code false} otherwise.
     */
    private boolean isRequestRequired(AccessRequestPattern pattern, Optional<DecisionResolution> resolution) {
        Instant deadline = Instant.now().plus(ACCESS_DECISION_VALIDITY_OFFSET);
        boolean isEnforceable = resolution.filter(enforced -> deadline.isBefore(enforced.validUntil())).isPresent();
        boolean isRequested = Optional.ofNullable(this.requestedFlows.get(pattern))
                .filter(deadline::isBefore).isPresent();
        if (isEnforceable) {
            // The decisions of the flow are current, so that the access request is due only if the flow itself was
            // never requested and this PEP enforces a decision of another flow for it.
            return !isRequested;
        }
        if (resolution.isPresent()) {
            // The decisions of the flow are about to expire and are renewed, whether or not another decision of the
            // flow was rejected: the suppression below concerns the flows for which this PEP enforces nothing.
            return true;
        }
        // An access decision that a verifying PDP did not confirm is not requested again before its verdict expires,
        // so that the outcome of the verification is not disclosed by repeated access requests.
        return !this.isRequestSuppressed(pattern);
    }

    /**
     * Retains that an access request was performed for a flow, so that it is repeated once the access decisions
     * received for that flow expire rather than once per data frame. The number of retained flows is bounded, so
     * that a PEP enforcing a flow per data frame pattern cannot exhaust its memory.
     *
     * @param pattern    the access request pattern the access request was performed for
     * @param resolution the resolution of the access decisions received for the flow
     */
    private void retainRequestedFlow(AccessRequestPattern pattern, Optional<DecisionResolution> resolution) {
        if (resolution.isEmpty()) {
            // Nothing was received for the flow, so that the next data frame requests again unless it is suppressed
            return;
        }
        if (this.requestedFlows.size() >= MAX_REQUESTED_FLOWS) {
            this.requestedFlows.clear();
        }
        this.requestedFlows.put(pattern, resolution.get().validUntil());
        this.requestedFlows.values().removeIf(instant -> instant.isBefore(Instant.now()));
    }

    /**
     * Suppresses the access requests for the data frames of a flow pattern until the given point in time, after
     * which the unverifiable access decision of that flow is requested and verified anew.
     *
     * @param pattern    the flow pattern of the unverifiable access decision
     * @param validUntil the point in time until the access requests are suppressed
     */
    private void suppressRequests(AccessRequestPattern pattern, Instant validUntil) {
        this.suppressedRequests.merge(pattern, validUntil,
                (current, update) -> current.isAfter(update) ? current : update);
        this.suppressedRequests.values().removeIf(instant -> instant.isBefore(Instant.now()));
    }

    /**
     * Checks whether the access requests for a data frame are suppressed, i.e. whether this PEP holds an unexpired
     * negative verdict for a flow pattern that matches the data frame.
     *
     * @param pattern the access request pattern of the data frame
     * @return {@code true} if no access request is to be performed, {@code false} otherwise.
     */
    private boolean isRequestSuppressed(AccessRequestPattern pattern) {
        Instant instant = Instant.now();
        return this.suppressedRequests.entrySet().stream()
                .anyMatch(entry -> instant.isBefore(entry.getValue()) && pattern.contains(entry.getKey()));
    }

    /**
     * Gets the directions whose decision cache an access decision is written into. A granting decision governs the
     * incoming data frames of this PEP if this PEP is one of its next hops, and the outgoing ones otherwise. A
     * decision that neither grants nor applies has an empty next hop set and may exclude a subset of a flow that is
     * granted in either direction, which is why it governs both directions.
     *
     * @param decision the access decision of a session initialization
     * @return the directions the access decision governs.
     */
    private Set<Direction> getDirections(AccessDecision decision) {
        if (!decision.isGranting()) {
            return EnumSet.allOf(Direction.class);
        }
        return decision.isNextHop(this.authorizationScope)
                ? EnumSet.of(Direction.INCOMING) : EnumSet.of(Direction.OUTGOING);
    }

    /**
     * Gets the address of the PDP that verifies the access decisions written into the decision cache of a direction.
     *
     * @param direction the direction in question
     * @return the address of the verifying PDP, or {@code null} if the verification is disabled for the direction.
     */
    private InetAddress getVerificationAuthority(Direction direction) {
        return direction == Direction.INCOMING
                ? this.incomingVerificationAuthority : this.outgoingVerificationAuthority;
    }

    /**
     * Gets the decision cache of a direction.
     *
     * @param direction the direction in question
     * @return the access decisions enforced for the data frames of the given direction.
     */
    private DecisionCache getDecisions(Direction direction) {
        return direction == Direction.INCOMING ? this.incomingDecisions : this.outgoingDecisions;
    }

    private boolean isVerificationAuthority(InetAddress address) {
        return Objects.nonNull(address) && (address.equals(this.incomingVerificationAuthority)
                || address.equals(this.outgoingVerificationAuthority));
    }

    private void releaseRequests(AccessDecision decision) {
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

    private void resolveVerifications(InetAddress authority, List<AccessDecisionVerdict> verdicts) {
        Set<AccessDecision> verifiedDecisions = verdicts.stream().map(AccessDecisionVerdict::getDecision)
                .collect(Collectors.toUnmodifiableSet());
        requestedVerifications.entrySet().stream().parallel()
                .filter(entry -> entry.getValue().isUnavailable()
                        && entry.getKey().authority().equals(authority)
                        && verifiedDecisions.containsAll(entry.getKey().decisions()))
                .forEach(entry -> entry.getValue().set(verdicts));
    }

    /**
     * Identifies the direction of the data frames that an access decision governs, and thereby the decision cache
     * the decision is written into and the PDP that verifies it.
     */
    private enum Direction {
        /**
         * The data frames this PEP receives from another PEP.
         */
        INCOMING,
        /**
         * The data frames this PEP receives from the SAS device it protects.
         */
        OUTGOING
    }

    /**
     * Identifies a pending access decision verification by the verifying PDP that it was requested from and by the
     * access decisions that it concerns. The verifying PDP is part of the identity, so that the response of one
     * verifying PDP cannot satisfy a verification requested from another one, e.g. if the verification of incoming
     * and of outgoing access decisions is delegated to two different PDPs.
     *
     * @param authority the address of the verifying PDP the verification was requested from
     * @param decisions the access decisions to be verified
     */
    private record PendingVerification(InetAddress authority, List<AccessDecision> decisions) {
    }

    /**
     * Identifies a retained {@link AccessDecisionVerdict verdict} by the verifying PDP that issued it and by the
     * {@link AccessDecision.Authorization authorization} it concerns. The verdict of one verifying PDP is therefore
     * not reused for the direction that another one verifies, whereas the renewed access decision of a policy
     * reuses the verdict of its predecessor, as the two state an equal authorization and a verdict is retained only
     * for as long as both PDPs vouch for their decision.
     *
     * @param authority     the address of the verifying PDP that issued the verdict
     * @param authorization the authorization the verdict concerns
     */
    private record RetainedVerdict(InetAddress authority, AccessDecision.Authorization authorization) {
    }
}
