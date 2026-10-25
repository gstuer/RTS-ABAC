package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.AccessDecision;
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
import com.gstuer.casc.common.pattern.IpPattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

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
    // Verification predicate
    //

    @Test
    public void testIdenticalDecisionAuthorizesSessionInitialization() {
        AccessDecision sessionInitialization = grant(pattern(), this.nextHop, 60);
        AccessDecision verification = grant(pattern(), this.nextHop, 60);
        assertTrue(AuthorizationManager.authorizes(verification, sessionInitialization));
    }

    @Test
    public void testDeviatingActionDoesNotAuthorizeSessionInitialization() {
        AccessDecision sessionInitialization = grant(pattern(), this.nextHop, 60);
        AccessDecision verification = new AccessDecision(pattern(), AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60));
        assertFalse(AuthorizationManager.authorizes(verification, sessionInitialization));
    }

    @Test
    public void testDeviatingNextHopDoesNotAuthorizeSessionInitialization() throws Exception {
        AccessDecision sessionInitialization = grant(pattern(), this.nextHop, 60);
        AccessDecision verification = grant(pattern(), InetAddress.getByName("127.0.0.9"), 60);
        assertFalse(AuthorizationManager.authorizes(verification, sessionInitialization));
    }

    @Test
    public void testExpiredVerificationDoesNotAuthorizeSessionInitialization() {
        AccessDecision sessionInitialization = grant(pattern(), this.nextHop, 60);
        AccessDecision verification = new AccessDecision(pattern(), AccessDecision.Action.GRANT, this.nextHop,
                Instant.now().minusSeconds(1));
        assertFalse(AuthorizationManager.authorizes(verification, sessionInitialization));
    }

    @Test
    public void testMoreGeneralVerificationAuthorizesSessionInitialization() throws Exception {
        // A verifying PDP may hold a less specific policy that still covers the flow of the session initialization.
        AccessRequestPattern specificPattern = new IpPattern(InetAddress.getByName("127.0.0.10"),
                InetAddress.getByName("127.0.0.11"), IpNumber.UDP, pattern());
        AccessDecision sessionInitialization = grant(specificPattern, this.nextHop, 60);
        AccessDecision verification = grant(pattern(), this.nextHop, 60);
        assertTrue(AuthorizationManager.authorizes(verification, sessionInitialization));
    }

    @Test
    public void testUnrelatedVerificationDoesNotAuthorizeSessionInitialization() {
        AccessRequestPattern unrelatedPattern = new EthernetPattern(DESTINATION_MAC, SOURCE_MAC, EtherType.ARP);
        AccessDecision sessionInitialization = grant(pattern(), this.nextHop, 60);
        AccessDecision verification = grant(unrelatedPattern, this.nextHop, 60);
        assertFalse(AuthorizationManager.authorizes(verification, sessionInitialization));
    }

    @Test
    public void testMissingVerificationDoesNotAuthorizeSessionInitialization() {
        assertFalse(AuthorizationManager.authorizes(null, grant(pattern(), this.nextHop, 60)));
    }

    //
    // Incoming session initializations
    //

    @Test
    public void testIncomingSessionInitializationIsInstalledWithoutVerification() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);

        manager.processMessage(this.sessionInitialization(decision));

        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
        assertTrue(this.egress.isEmpty(), "No verification request must be sent if verification is disabled.");
    }

    @Test
    public void testIncomingSessionInitializationIsInstalledAfterMatchingVerification() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecision decision = grant(pattern(), this.scope, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        Thread worker = startThread(() -> manager.processMessage(message));
        AccessControlMessage<?> request = this.pollEgress();
        assertInstanceOf(AccessVerificationRequestMessage.class, request);
        assertEquals(this.verificationAuthority, request.getDestination());
        assertEquals(decision.getPattern(), request.getPayload());
        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent(),
                "An unverified session initialization must not be effective.");

        manager.processMessage(this.verification(grant(pattern(), this.scope, 60)));
        join(worker);

        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    @Test
    public void testIncomingSessionInitializationIsDiscardedAfterDeviatingVerification() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecisionMessage message = this.sessionInitialization(grant(pattern(), this.scope, 60));

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        AccessDecision deviating = new AccessDecision(pattern(), AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60));
        manager.processMessage(this.verification(deviating));
        join(worker);

        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    @Test
    public void testVerificationFromUnknownAuthorityIsIgnored() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority, null);
        AccessDecisionMessage message = this.sessionInitialization(grant(pattern(), this.scope, 60));

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        // A response of the issuing PDP must not satisfy the verification against the verifying PDP.
        manager.processMessage(this.signedVerification(grant(pattern(), this.scope, 60), this.authorizationAuthority));
        assertFalse(manager.authorizeIncoming(this.payloadExchange()).isPresent());

        manager.processMessage(this.verification(grant(pattern(), this.scope, 60)));
        join(worker);
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    @Test
    public void testSessionInitializationsOfBothDirectionsAreVerifiedByTheirOwnAuthority() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority,
                this.secondVerificationAuthority);

        // A session initialization whose next hop is this PEP is incoming, any other one is outgoing
        Thread incoming = startThread(() -> manager.processMessage(this.sessionInitialization(this.scope)));
        AccessControlMessage<?> incomingRequest = this.pollEgress();
        Thread outgoing = startThread(() -> manager.processMessage(this.sessionInitialization(this.nextHop)));
        AccessControlMessage<?> outgoingRequest = this.pollEgress();

        // Each direction must be verified by the PDP configured for it
        assertInstanceOf(AccessVerificationRequestMessage.class, incomingRequest);
        assertInstanceOf(AccessVerificationRequestMessage.class, outgoingRequest);
        assertEquals(this.verificationAuthority, incomingRequest.getDestination());
        assertEquals(this.secondVerificationAuthority, outgoingRequest.getDestination());

        manager.processMessage(this.verification(grant(pattern(), this.scope, 60)));
        manager.processMessage(this.signedVerification(grant(pattern(), this.nextHop, 60),
                this.secondVerificationAuthority));
        join(incoming);
        join(outgoing);
        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent());
    }

    @Test
    public void testVerificationDoesNotSatisfyAVerificationRequestedFromAnotherAuthority() throws Exception {
        AuthorizationManager manager = this.createManager(this.verificationAuthority,
                this.secondVerificationAuthority);

        Thread incoming = startThread(() -> manager.processMessage(this.sessionInitialization(this.scope)));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());
        Thread outgoing = startThread(() -> manager.processMessage(this.sessionInitialization(this.nextHop)));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        // The response of the PDP verifying the incoming traffic must leave the verification of the outgoing session
        // initialization pending, which the PEP signals by repeating its request to the responsible PDP.
        manager.processMessage(this.verification(grant(pattern(), this.scope, 60)));
        join(incoming);
        AccessControlMessage<?> repeatedRequest = this.pollEgress();
        assertInstanceOf(AccessVerificationRequestMessage.class, repeatedRequest);
        assertEquals(this.secondVerificationAuthority, repeatedRequest.getDestination());

        manager.processMessage(this.signedVerification(grant(pattern(), this.nextHop, 60),
                this.secondVerificationAuthority));
        join(outgoing);
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

        manager.processMessage(this.verification(grant(pattern(), this.nextHop, 60)));
        join(worker);
        join(frame);

        assertEquals(1, result.get().size(), "The held frame must be forwarded once the decision is verified.");
        assertEquals(this.nextHop, result.get().get(0).getDestination());
    }

    @Test
    public void testHeldFrameIsDroppedAfterDeviatingVerification() throws Exception {
        AuthorizationManager manager = this.createManager(null, this.verificationAuthority);
        AccessDecisionMessage message = this.sessionInitialization(grant(pattern(), this.nextHop, 60));

        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        AccessDecision deviating = new AccessDecision(pattern(), AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60));
        manager.processMessage(this.verification(deviating));
        join(worker);
        join(frame);

        assertTrue(result.get().isEmpty(), "The held frame must be dropped if the session initialization is unverifiable.");
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
        AccessDecision denying = new AccessDecision(pattern(), AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60));
        AccessDecisionMessage message = this.sessionInitialization(granting, denying);

        // The data frame finds no decision, triggers an access request, and is held
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        // The granting decision is verified first and must not release the held frame on its own
        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());
        manager.processMessage(this.signedVerification(granting, this.verificationAuthority));

        // The denying decision of the same session initialization is verified next
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());
        manager.processMessage(this.signedVerification(denying, this.verificationAuthority));
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
        manager.processMessage(this.sessionInitialization(decision));

        List<PayloadExchangeMessage> messages = manager.authorizeOutgoing(packet());
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
        manager.processMessage(this.sessionInitialization(grant(pattern(), this.scope, 60),
                grant(pattern(), this.nextHop, 60)));

        assertTrue(manager.authorizeIncoming(this.payloadExchange()).isPresent(),
                "The decision naming this PEP as next hop governs the incoming data frames.");
        assertEquals(1, manager.authorizeOutgoing(packet()).size(),
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
        manager.processMessage(this.sessionInitialization(decision));
        this.egress.clear();

        assertTrue(manager.authorizeOutgoing(packet()).isEmpty(), "A frame without an applicable policy is dropped.");
        assertTrue(this.egress.isEmpty(), "A matching decision must not trigger a repeated access request.");
    }

    /**
     * A denying access decision is enforced for its period of validity, so that the data frames of a denied flow are
     * dropped without an access request per data frame.
     */
    @Test
    public void testDenyingDecisionDropsOutgoingFrameWithoutAnAccessRequest() throws Exception {
        AuthorizationManager manager = this.createManager(null, null);
        AccessDecision decision = new AccessDecision(pattern(), AccessDecision.Action.DENY, Set.of(),
                Instant.now().plusSeconds(60));
        manager.processMessage(this.sessionInitialization(decision));
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
        // The shorter-lived decision is valid, but expires within the validity offset of the PEP.
        AccessDecision expiring = new AccessDecision(pattern(), AccessDecision.Action.GRANT, Set.of(this.nextHop),
                Instant.now().plusMillis(99));
        AccessDecision longLived = grant(pattern(), this.nextHop, 60);
        AccessDecisionMessage message = this.sessionInitialization(expiring, longLived);
        AccessDecisionMessage renewal = this.sessionInitialization(grant(pattern(), this.nextHop, 60));
        this.egress.clear();
        manager.processMessage(message);

        // The data frame triggers a renewal although the longer-lived decision still grants it
        AtomicReference<List<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress(),
                "An access decision that expires within the validity offset has to be renewed.");

        manager.processMessage(renewal);
        join(frame);
        assertEquals(1, result.get().size(), "The held frame is forwarded once the renewal arrived.");
        assertEquals(this.nextHop, result.get().get(0).getDestination());
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

    private static AccessDecision grant(AccessRequestPattern pattern, InetAddress nextHop, long validitySeconds) {
        return new AccessDecision(pattern, AccessDecision.Action.GRANT, nextHop,
                Instant.now().plusSeconds(validitySeconds));
    }

    private PayloadExchangeMessage payloadExchange() {
        return new PayloadExchangeMessage(this.authorizationAuthority, this.scope, null, packet());
    }

    private AccessDecisionMessage sessionInitialization(InetAddress nextHop) {
        try {
            return this.sessionInitialization(grant(pattern(), nextHop, 60));
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private AccessDecisionMessage sessionInitialization(AccessDecision... decisions) throws Exception {
        return new AccessDecisionMessage(this.authorizationAuthority, this.scope, null, List.of(decisions))
                .sign(remoteAuthenticator());
    }

    private AccessVerificationMessage verification(AccessDecision decision) throws Exception {
        return this.signedVerification(decision, this.verificationAuthority);
    }

    private AccessVerificationMessage signedVerification(AccessDecision decision, InetAddress source) throws Exception {
        return new AccessVerificationMessage(source, this.scope, null, decision).sign(remoteAuthenticator());
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
