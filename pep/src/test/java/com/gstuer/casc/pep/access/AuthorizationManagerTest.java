package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessDecisionVerdict;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.message.AccessVerificationMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import com.gstuer.casc.common.pattern.PatternFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV4TosPrecedence;
import org.pcap4j.packet.namednumber.IpV4TosTos;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthorizationManagerTest {
    private static final MacAddress SOURCE_MAC = MacAddress.getByName("00:00:00:00:00:00");
    private static final MacAddress DESTINATION_MAC = MacAddress.getByName("ff:ff:ff:ff:ff:ff");
    private static final long TIMEOUT_SECONDS = 5;

    private BlockingQueue<AccessControlMessage<?>> egress;
    private AuthenticationClient authenticationClient;
    private InetAddress scope;
    private InetAddress authorizationAuthority;
    private InetAddress verificationAuthority;
    private InetAddress secondVerificationAuthority;
    private InetAddress nextHop;
    private InetAddress secondNextHop;

    @BeforeEach
    public void setUp() throws Exception {
        this.egress = new LinkedBlockingQueue<>();
        this.scope = InetAddress.getByName("127.0.0.1");
        this.authorizationAuthority = InetAddress.getByName("127.0.0.2");
        this.verificationAuthority = InetAddress.getByName("127.0.0.3");
        this.secondVerificationAuthority = InetAddress.getByName("127.0.0.5");
        this.nextHop = InetAddress.getByName("127.0.0.4");
        this.secondNextHop = InetAddress.getByName("127.0.0.6");

        // The no-operation authenticator accepts every signature, so no key exchange over the network is required.
        this.authenticationClient = new AuthenticationClient(this.authorizationAuthority,
                new NoOperationAuthenticator(), this.egress);
        this.seedVerifier(this.authorizationAuthority);
        this.seedVerifier(this.verificationAuthority);
        this.seedVerifier(this.secondVerificationAuthority);
        this.egress.clear();
    }

    //
    // Server-aided verification of the access decisions of a session initialization
    //

    @Test
    public void testIncomingSessionInitializationIsInstalledWithoutVerification() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);

        manager.processMessage(this.sessionInitialization(decision));

        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
        assertTrue(this.egress.isEmpty(), "No verification request must be sent if verification is disabled.");
    }

    /**
     * A PEP submits the access decisions of a session initialization to the PDP that verifies the direction they
     * govern, and enforces them once that PDP confirms them. The decisions themselves are submitted rather than
     * their flow pattern, so that the response states a verdict per decision.
     */
    @Test
    public void testIncomingDecisionIsInstalledAfterItIsConfirmed() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        Thread worker = startThread(() -> manager.processMessage(message));
        AccessControlMessage<?> request = this.pollEgress();
        assertInstanceOf(AccessVerificationRequestMessage.class, request);
        assertEquals(this.verificationAuthority, request.getDestination());
        assertEquals(List.of(decision), request.getPayload(), "The decisions to be verified are submitted.");
        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent(),
                "An unverified access decision must not be effective.");

        manager.processMessage(this.verification(decision));
        join(worker);

        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    /**
     * An access decision that the verifying PDP does not confirm is discarded, i.e. it is not written into the
     * decision cache of the direction that PDP verifies.
     */
    @Test
    public void testIncomingDecisionIsDiscardedAfterItIsRejected() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        manager.processMessage(this.verification(this.verificationAuthority, reject(decision)));
        join(worker);

        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    /**
     * The verdicts of a PDP that verifies no direction of this PEP are ignored, so that a response of the issuing
     * PDP cannot satisfy the verification of its own session initialization.
     */
    @Test
    public void testVerificationFromUnknownAuthorityIsIgnored() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        manager.processMessage(this.verification(this.authorizationAuthority, confirm(decision)));
        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent());

        manager.processMessage(this.verification(decision));
        join(worker);
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    /**
     * A session initialization is verified in one request per verifying PDP rather than one per access decision, so
     * that its verification costs one round trip per PDP. Each PDP receives exactly the decisions written into the
     * cache of the direction it verifies.
     */
    @Test
    public void testDecisionsOfOneDirectionAreVerifiedInOneRequest() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision firstDecision = grant(pattern(), this.scope, 60);
        AccessDecision secondDecision = grant(specificPattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(firstDecision, secondDecision);

        Thread worker = startThread(() -> manager.processMessage(message));
        AccessControlMessage<?> request = this.pollEgress();
        assertInstanceOf(AccessVerificationRequestMessage.class, request);
        assertEquals(List.of(firstDecision, secondDecision), request.getPayload(),
                "Both decisions of the session initialization are verified in one request.");

        manager.processMessage(this.verification(firstDecision, secondDecision));
        join(worker);
        assertTrue(this.egress.isEmpty(), "One round trip per verifying PDP has to suffice.");
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    /**
     * Each verifying PDP vouches for the decisions written into the cache of its own direction, so that the
     * decisions of a session initialization are split between the two PDPs by the direction they govern.
     */
    @Test
    public void testDecisionsOfBothDirectionsAreVerifiedByTheirOwnAuthority() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority,
                this.secondVerificationAuthority);
        AccessDecision incomingDecision = grant(pattern(), this.scope, 60);
        AccessDecision outgoingDecision = grant(pattern(), this.nextHop, 60);
        AccessDecisionMessage message = this.sessionInitialization(incomingDecision, outgoingDecision);

        // A data frame of the flow awaits the session initialization, so that the outgoing decision is enforced
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        // The two verifying PDPs are requested one after another, in no particular order
        Thread worker = startThread(() -> manager.processMessage(message));
        Map<InetAddress, List<AccessDecision>> requests = new HashMap<>();
        for (int request = 0; request < 2; request++) {
            AccessControlMessage<?> verificationRequest = this.pollEgress();
            assertInstanceOf(AccessVerificationRequestMessage.class, verificationRequest);
            List<AccessDecision> decisions = ((AccessVerificationRequestMessage) verificationRequest).getPayload();
            requests.put(verificationRequest.getDestination(), decisions);
            manager.processMessage(this.verification(verificationRequest.getDestination(),
                    decisions.stream().map(this::confirm).toArray(AccessDecisionVerdict[]::new)));
        }
        join(worker);
        join(frame);

        // Each PDP verifies exactly the decisions of its own direction
        assertEquals(List.of(incomingDecision), requests.get(this.verificationAuthority));
        assertEquals(List.of(outgoingDecision), requests.get(this.secondVerificationAuthority));
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
        assertEquals(1, result.get().size());
    }

    /**
     * A denying or non-applicable access decision has an empty next hop set and is written into the cache of both
     * directions, so that it requires the green light of both verifying PDPs. If only one of them confirms it, the
     * decision constrains only the direction of the confirming PDP: here the outgoing PDP rejects the denial, so
     * that the granting decision of the same session initialization remains in force for the outgoing data frames.
     */
    @Test
    public void testDecisionOfBothDirectionsRequiresBothAuthorities() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority,
                this.secondVerificationAuthority);
        AccessDecision grant = grant(pattern(), this.nextHop, 60);
        AccessDecision denial = deny(pattern(), 60);
        AccessDecisionMessage message = this.sessionInitialization(grant, denial);

        // A data frame of the flow awaits the session initialization, so that the outgoing decisions are enforced
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        // The PDP of the incoming direction confirms the denial, the one of the outgoing direction rejects it
        Thread worker = startThread(() -> manager.processMessage(message));
        for (int request = 0; request < 2; request++) {
            AccessControlMessage<?> verificationRequest = this.pollEgress();
            InetAddress authority = verificationRequest.getDestination();
            List<AccessDecision> decisions = ((AccessVerificationRequestMessage) verificationRequest).getPayload();
            assertTrue(decisions.contains(denial), "The denial is verified by both PDPs.");
            AccessDecisionVerdict[] verdicts = decisions.stream()
                    .map(decision -> authority.equals(this.secondVerificationAuthority) && decision.isDenying()
                            ? this.reject(decision) : this.confirm(decision))
                    .toArray(AccessDecisionVerdict[]::new);
            manager.processMessage(this.verification(authority, verdicts));
        }
        join(worker);
        join(frame);

        // The outgoing cache holds the grant alone, as its PDP did not confirm the denial
        assertEquals(1, result.get().size(),
                "A denial that the outgoing PDP rejects must not constrain the outgoing data frames.");
    }

    /**
     * The decision cache of a direction follows the verdict of the PDP that verifies that direction. A denial that
     * governs both directions therefore constrains the incoming data frames if and only if the PDP verifying the
     * incoming direction confirms it, independently of the verdict of the other PDP.
     */
    @Test
    public void testIncomingCacheFollowsTheVerdictOfTheIncomingAuthority() throws Exception {
        assertFalse(this.isIncomingFrameAccepted(true),
                "A denial confirmed for the incoming direction overrides the grant of the same flow.");
        assertTrue(this.isIncomingFrameAccepted(false),
                "A denial rejected for the incoming direction leaves the grant of the same flow in force.");
    }

    /**
     * The renewed access decision of a policy reuses the verdict of its predecessor, as the two state an equal
     * authorization and differ in their period of validity only. A renewal therefore costs no verification round
     * trip in addition to the access request, for as long as the verdict of the authorization holds.
     */
    @Test
    public void testRenewedDecisionReusesTheVerdictOfItsPredecessor() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());
        manager.processMessage(this.verification(decision));
        join(worker);
        this.egress.clear();

        // The renewal states the same authorization for a longer period of validity
        AccessDecision renewedDecision = grant(pattern(), this.scope, 120);
        assertEquals(decision.getAuthorization(), renewedDecision.getAuthorization());
        manager.processMessage(this.sessionInitialization(renewedDecision));

        assertTrue(this.egress.isEmpty(), "A renewed decision must not be verified again.");
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    /**
     * The verdicts of one verifying PDP must not satisfy a verification requested from another one, e.g. if the
     * verification of the incoming and of the outgoing direction is delegated to two different PDPs. The PEP signals
     * the unsatisfied verification by repeating its request to the PDP it is waiting for.
     */
    @Test
    public void testVerdictsDoNotSatisfyAVerificationRequestedFromAnotherAuthority() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority,
                this.secondVerificationAuthority);
        AccessDecision denial = deny(pattern(), 60);
        AccessDecisionMessage message = this.sessionInitialization(denial);

        // A denial governs both directions, so that both PDPs are asked one after another
        Thread worker = startThread(() -> manager.processMessage(message));
        InetAddress awaitedAuthority = this.pollEgress().getDestination();
        InetAddress otherAuthority = awaitedAuthority.equals(this.verificationAuthority)
                ? this.secondVerificationAuthority : this.verificationAuthority;

        // The verdict of the PDP that was not asked yet must leave the pending verification unsatisfied, which the
        // PEP signals by repeating its request to the awaited PDP.
        manager.processMessage(this.verification(otherAuthority, confirm(denial)));
        assertEquals(awaitedAuthority, this.pollVerificationRequest(awaitedAuthority).getDestination());

        manager.processMessage(this.verification(awaitedAuthority, confirm(denial)));
        this.pollVerificationRequest(otherAuthority);
        manager.processMessage(this.verification(otherAuthority, confirm(denial)));
        join(worker);
    }

    /**
     * A verdict is retained for its period of validity, so that a session initialization whose decisions were
     * verified before is enforced without a further round trip. Without it, every renewal of an access decision
     * would cost a verification round trip in addition to the access request.
     */
    @Test
    public void testRetainedVerdictAvoidsAFurtherVerification() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());
        manager.processMessage(this.verification(decision));
        join(worker);
        this.egress.clear();

        // The same session initialization is processed again, which must not block on a verification
        manager.processMessage(message);

        assertTrue(this.egress.isEmpty(), "A retained verdict must not be requested again.");
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    //
    // Outgoing session initializations and the data frame that triggers them
    //

    @Test
    public void testHeldFrameIsForwardedAfterMatchingVerification() throws Exception {
        AuthorizationManager manager = this.createManager(null, this.verificationAuthority);
        AccessDecision decision = grant(pattern(), this.nextHop, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        // The data frame finds no decision, triggers an access request, and is held
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        // The session initialization is held until the verifying PDP confirmed it
        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        manager.processMessage(this.verification(decision));
        join(worker);
        join(frame);

        assertEquals(1, result.get().size(), "The held frame must be forwarded once the decision is verified.");
        assertEquals(this.nextHop, result.get().get(0).getDestination());
    }

    /**
     * A data frame that awaits a session initialization whose decisions are rejected is dropped, and the outcome of
     * the verification is not disclosed: the data frames that follow are dropped without a repeated access request
     * for as long as the negative verdict holds. Without that, the PEP would request an access decision per data
     * frame of the flow and thereby reveal the outcome to the issuing PDP.
     */
    @Test
    public void testRejectedDecisionSuppressesTheRepeatedAccessRequest() throws Exception {
        AuthorizationManager manager = this.createManager(null, this.verificationAuthority);
        AccessDecision decision = grant(pattern(), this.nextHop, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());
        manager.processMessage(this.verification(this.verificationAuthority, reject(decision)));
        join(worker);
        join(frame);
        assertTrue(result.get().isEmpty(), "The held frame must be dropped if its decision is unverifiable.");
        this.egress.clear();

        // The next data frame of the flow is dropped without any further message being sent
        assertTrue(manager.authorizeOutgoing(packet()).isEmpty());
        assertTrue(this.egress.isEmpty(), "A rejected access decision must not be requested again.");
    }

    /**
     * A verifying PDP that does not respond keeps the session initialization from becoming effective, as a PEP
     * enforces an access decision only if the PDP of its direction vouched for it.
     */
    @Test
    public void testUnreachableAuthorityDiscardsTheSessionInitialization() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);

        manager.processMessage(this.sessionInitialization(decision));

        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    /**
     * A data frame that awaits a session initialization is released only once all access decisions of that session
     * initialization are installed, as its enforcement resolves the conflicts between all of them. The test holds a
     * frame that awaits a granting and a denying decision of one session initialization and delays the verification
     * of the denying one, so that releasing the frame prematurely would forward it although the session initialization
     * denies it.
     */
    @Test
    public void testHeldFrameIsReleasedAfterTheWholeSessionInitializationIsInstalled() throws Exception {
        AuthorizationManager manager = this.createManager(null, this.verificationAuthority);
        AccessDecision granting = grant(pattern(), this.nextHop, 60);
        AccessDecision denying = deny(pattern(), 60);
        AccessDecisionMessage message = this.sessionInitialization(granting, denying);

        // The data frame finds no decision, triggers an access request, and is held
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        // Both decisions are verified in one request, which the frame has to await
        Thread worker = startThread(() -> manager.processMessage(message));
        AccessControlMessage<?> request = this.pollEgress();
        assertInstanceOf(AccessVerificationRequestMessage.class, request);
        assertEquals(List.of(granting, denying), request.getPayload());

        manager.processMessage(this.verification(granting, denying));
        join(worker);
        join(frame);

        assertTrue(result.get().isEmpty(),
                "A denying decision of the session initialization must override the granting one.");
    }

    //
    // Decision enforcement for the two directions of a data frame flow
    //

    /**
     * An outgoing data frame is forwarded to each next hop of the access decision that grants it, so that a decision
     * permitting several recipients yields one payload exchange message per recipient.
     */
    @Test
    public void testOutgoingFrameIsForwardedToEachNextHop() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        AccessDecision decision = new AccessDecision(pattern(), AccessDecision.Action.GRANT,
                Set.of(this.nextHop, this.secondNextHop), Instant.now().plusSeconds(60));

        List<PayloadExchangeMessage> messages = this.establishOutgoingFlow(manager, decision);

        assertEquals(2, messages.size());
        assertEquals(Set.of(this.nextHop, this.secondNextHop),
                messages.stream().map(PayloadExchangeMessage::getDestination).collect(Collectors.toSet()));
    }

    /**
     * An incoming data frame is accepted only by a PEP that the granting access decision permits as a recipient. A
     * PEP that is not a next hop of the decision drops the data frame, even though the decision grants the flow.
     */
    @Test
    public void testIncomingFrameIsRejectedByAPepThatIsNoNextHop() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        manager.processMessage(this.sessionInitialization(grant(pattern(), this.nextHop, 60)));

        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent(),
                "A PEP must not accept the data frames of a flow it is no next hop of.");
    }

    /**
     * A session initialization contains one or multiple access decisions, all of which a PEP adds to its local
     * session state. A single session initialization therefore suffices to govern both directions of a bidirectional
     * exchange between two SAS devices.
     */
    @Test
    public void testSessionInitializationWithSeveralDecisionsInstallsAllOfThem() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);

        List<PayloadExchangeMessage> messages = this.establishOutgoingFlow(manager,
                grant(pattern(), this.scope, 60), grant(pattern(), this.nextHop, 60));

        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent(),
                "The decision naming this PEP as next hop governs the incoming data frames.");
        assertEquals(1, messages.size(),
                "The decision naming another PEP as next hop governs the outgoing data frames.");
    }

    /**
     * A PEP distinguishes the absence of an applicable access decision from the absence of an access decision. If it
     * holds a valid decision whose flow pattern matches the data frame but whose policy does not apply, no policy
     * applies to the frame, so that the frame is dropped without repeating the access request for it.
     */
    @Test
    public void testNonApplicableDecisionDropsOutgoingFrameWithoutAnAccessRequest() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        AccessDecision decision = new AccessDecision(pattern(), AccessDecision.Action.NOTAPPLICABLE, Set.of(),
                Instant.now().plusSeconds(60));
        assertTrue(this.establishOutgoingFlow(manager, decision).isEmpty(),
                "A frame without an applicable policy is dropped.");
        this.egress.clear();

        assertTrue(manager.authorizeOutgoing(packet()).isEmpty());
        assertTrue(this.egress.isEmpty(), "A matching decision must not trigger a repeated access request.");
    }

    /**
     * A denying access decision is enforced for its period of validity, so that the data frames of a denied flow are
     * dropped without an access request per data frame.
     */
    @Test
    public void testDenyingDecisionDropsOutgoingFrameWithoutAnAccessRequest() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        assertTrue(this.establishOutgoingFlow(manager, deny(pattern(), 60)).isEmpty());
        this.egress.clear();

        assertTrue(manager.authorizeOutgoing(packet()).isEmpty());
        assertTrue(this.egress.isEmpty(), "A retained denial must not trigger a repeated access request.");
    }

    /**
     * A PEP renews the access decisions of a flow before the first of the decisions it enforces for that flow
     * expires, as that is the point in time at which a composite decision expires. A longer-lived decision of the
     * same flow must not suppress the renewal: it would otherwise take over silently once the shorter-lived decision
     * expired, e.g. a general grant taking over from a denial that excludes a subset of the granted flow, and the
     * PEP would never ask the PDP again.
     */
    @Test
    public void testOutgoingFrameRenewsTheDecisionsBeforeTheEarliestOfThemExpires() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        // The two decisions permit different recipients, so that both of them are enforced and the resolution is
        // their composite decision. The shorter-lived one is valid, but expires within the validity offset.
        AccessDecision expiring = new AccessDecision(pattern(), AccessDecision.Action.GRANT,
                Set.of(this.secondNextHop), Instant.now().plusMillis(99));
        AccessDecision longLived = grant(pattern(), this.nextHop, 60);
        AccessDecisionMessage message = this.sessionInitialization(expiring, longLived);
        AccessDecisionMessage renewal = this.sessionInitialization(grant(pattern(), this.nextHop, 60));
        this.egress.clear();
        manager.processMessage(message);

        // The data frame triggers a renewal although the longer-lived decision still grants it
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress(),
                "A composite decision that expires within the validity offset has to be renewed.");

        manager.processMessage(renewal);
        join(frame);
        assertFalse(result.get().isEmpty(), "The held frame is forwarded once the renewal arrived.");
        assertTrue(result.get().stream().map(PayloadExchangeMessage::getDestination)
                        .anyMatch(this.nextHop::equals),
                "The renewed decision permits the recipient it names.");
    }

    /**
     * An access request is performed for the first data frame of a flow even if an access decision of another flow
     * already matches that data frame. A PEP would otherwise enforce the policy set of whichever flow happened to be
     * requested first: a denial that excludes this flow from a more generally granted one would never reach it, so
     * that the same policy set would grant or deny a flow depending on the order of the access requests.
     */
    @Test
    public void testFlowIsRequestedAlthoughADecisionOfAnotherFlowMatchesIt() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);

        // The flow of the Ethernet pattern is established, whose granting decision also matches the UDP flow below
        assertEquals(1, this.establishOutgoingFlow(manager, grant(pattern(), this.nextHop, 60)).size());
        this.egress.clear();

        // A data frame of the UDP flow triggers the access request of its own flow, which is denied
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(specificPacket())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress(),
                "The first data frame of a flow has to trigger an access request for that flow.");
        manager.processMessage(this.sessionInitialization(deny(specificPattern(), 60),
                grant(pattern(), this.nextHop, 60)));
        join(frame);

        assertTrue(result.get().isEmpty(), "The denial of the requested flow has to be enforced.");
    }

    //
    // Test fixture
    //

    private AuthorizationManager createManager(InetAddress incoming, InetAddress outgoing) {
        return new AuthorizationManager(this.authorizationAuthority, this.scope, incoming, outgoing,
                this.authenticationClient, this.egress);
    }

    private static AccessRequestPattern pattern() {
        return new EthernetPattern(SOURCE_MAC, DESTINATION_MAC, EtherType.IPV4);
    }

    private static Packet packet() {
        return new EthernetPacket.Builder()
                .srcAddr(SOURCE_MAC)
                .dstAddr(DESTINATION_MAC)
                .type(EtherType.IPV4)
                .paddingAtBuild(true)
                .build();
    }

    private static AccessRequestPattern specificPattern() throws UnknownHostException {
        return PatternFactory.derivePatternFrom(specificPacket());
    }

    /**
     * Builds a data frame of a UDP flow between the two devices of {@link #packet()}, whose access request pattern
     * is therefore more specific than the Ethernet pattern of that data frame.
     */
    private static Packet specificPacket() {
        try {
            return new EthernetPacket.Builder()
                    .srcAddr(SOURCE_MAC)
                    .dstAddr(DESTINATION_MAC)
                    .type(EtherType.IPV4)
                    .paddingAtBuild(true)
                    .payloadBuilder(new IpV4Packet.Builder()
                            .version(IpVersion.IPV4)
                            .tos(new IpV4Rfc1349Tos.Builder()
                                    .precedence(IpV4TosPrecedence.ROUTINE)
                                    .tos(IpV4TosTos.DEFAULT)
                                    .build())
                            .srcAddr((Inet4Address) Inet4Address.getByName("192.168.0.50"))
                            .dstAddr((Inet4Address) Inet4Address.getByName("192.168.0.51"))
                            .protocol(IpNumber.UDP)
                            .payloadBuilder(new UdpPacket.Builder()
                                    .srcAddr(Inet4Address.getByName("192.168.0.50"))
                                    .srcPort(new UdpPort((short) 10001, "SABAAC"))
                                    .dstAddr(Inet4Address.getByName("192.168.0.51"))
                                    .dstPort(new UdpPort((short) 10000, "SABAAC"))))
                    .build();
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static AccessDecision grant(AccessRequestPattern pattern, InetAddress nextHop, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.GRANT, nextHop,
                Instant.now().plusSeconds(validitySeconds));
    }

    private static AccessDecision deny(AccessRequestPattern pattern, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(validitySeconds));
    }

    private PayloadExchangeMessage payloadExchange() {
        return new PayloadExchangeMessage(this.authorizationAuthority, this.scope, null, packet());
    }

    private AccessDecisionMessage sessionInitialization(AccessDecision... decisions) throws Exception {
        return new AccessDecisionMessage(this.authorizationAuthority, this.scope, null, List.of(decisions))
                .sign(remoteAuthenticator());
    }

    private AccessVerificationMessage verification(AccessDecision... decisions) throws Exception {
        AccessDecisionVerdict[] verdicts = Stream.of(decisions).map(this::confirm)
                .toArray(AccessDecisionVerdict[]::new);
        return this.verification(this.verificationAuthority, verdicts);
    }

    private AccessVerificationMessage verification(InetAddress source, AccessDecisionVerdict... verdicts)
            throws Exception {
        return new AccessVerificationMessage(source, this.scope, null, List.of(verdicts))
                .sign(remoteAuthenticator());
    }

    private AccessDecisionVerdict confirm(AccessDecision decision) {
        return new AccessDecisionVerdict(decision, true, Instant.now().plusSeconds(60));
    }

    private AccessDecisionVerdict reject(AccessDecision decision) {
        return new AccessDecisionVerdict(decision, false, Instant.now().plusSeconds(60));
    }

    private void seedVerifier(InetAddress host) throws InvalidKeyException, SignatureException {
        NoOperationAuthenticator remote = remoteAuthenticator();
        EncodedKey encodedKey = new EncodedKey(NoOperationAuthenticator.ALGORITHM_IDENTIFIER,
                remote.getVerificationKey().getEncoded());
        this.authenticationClient.processMessage(
                new KeyExchangeMessage(host, this.scope, null, encodedKey).sign(remote));
    }

    private static NoOperationAuthenticator remoteAuthenticator() {
        NoOperationAuthenticator authenticator = new NoOperationAuthenticator();
        authenticator.initializeKeyPair();
        return authenticator;
    }

    /**
     * Processes a session initialization of a granting decision for this PEP and a denying decision of an equal flow
     * pattern, where the PDP verifying the incoming direction either confirms or rejects the denial while the PDP
     * verifying the outgoing direction confirms everything.
     *
     * @param confirmDenial whether the PDP of the incoming direction confirms the denying access decision
     * @return {@code true} if an incoming data frame of the flow is accepted afterwards, {@code false} otherwise.
     */
    private boolean isIncomingFrameAccepted(boolean confirmDenial) throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority,
                this.secondVerificationAuthority);
        AccessDecision grant = grant(pattern(), this.scope, 60);
        AccessDecision denial = deny(pattern(), 60);
        AccessDecisionMessage message = this.sessionInitialization(grant, denial);

        Thread worker = startThread(() -> manager.processMessage(message));
        for (int request = 0; request < 2; request++) {
            AccessControlMessage<?> verificationRequest = this.pollEgress();
            InetAddress authority = verificationRequest.getDestination();
            AccessDecisionVerdict[] verdicts = ((AccessVerificationRequestMessage) verificationRequest).getPayload()
                    .stream()
                    .map(decision -> decision.isDenying() && !confirmDenial
                            && authority.equals(this.verificationAuthority)
                            ? this.reject(decision) : this.confirm(decision))
                    .toArray(AccessDecisionVerdict[]::new);
            manager.processMessage(this.verification(authority, verdicts));
        }
        join(worker);
        return manager.authorizeIncoming(this.payloadExchange()).isPresent();
    }

    /**
     * Establishes an outgoing flow the way the protocol does: a data frame of the flow triggers the access request,
     * the session initialization answers it, and the data frame is enforced from the decisions it contains. An
     * access request is performed once per flow, so that a decision installed without a request of its flow does
     * not authorize the data frames of that flow.
     *
     * @param manager   the authorization manager under test
     * @param decisions the access decisions of the session initialization
     * @return the payload exchange messages that the triggering data frame yielded.
     */
    private List<PayloadExchangeMessage> establishOutgoingFlow(AuthorizationManager manager,
                                                               AccessDecision... decisions) throws Exception {
        AccessDecisionMessage message = this.sessionInitialization(decisions);
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());
        manager.processMessage(message);
        join(frame);
        return result.get();
    }

    private AccessControlMessage<?> pollVerificationRequest(InetAddress destination) throws InterruptedException {
        // Requests repeated to another PDP are skipped, as a pending verification is retried every 250 milliseconds.
        for (AccessControlMessage<?> message = this.pollEgress(); Objects.nonNull(message); message = this.pollEgress()) {
            if (message instanceof AccessVerificationRequestMessage && destination.equals(message.getDestination())) {
                return message;
            }
        }
        throw new AssertionError("No verification request was sent to " + destination.getHostAddress());
    }

    private AccessControlMessage<?> pollEgress() throws InterruptedException {
        return this.egress.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private static Thread startThread(Runnable runnable) {
        Thread thread = new Thread(runnable);
        thread.start();
        return thread;
    }

    private static void join(Thread thread) throws InterruptedException {
        thread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        assertFalse(thread.isAlive(), "The processing thread must terminate.");
    }
}
