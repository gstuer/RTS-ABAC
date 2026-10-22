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
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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
    private InetAddress nextHop;

    @BeforeEach
    public void setUp() throws Exception {
        this.egress = new LinkedBlockingQueue<>();
        this.scope = InetAddress.getByName("127.0.0.1");
        this.authorizationAuthority = InetAddress.getByName("127.0.0.2");
        this.verificationAuthority = InetAddress.getByName("127.0.0.3");
        this.nextHop = InetAddress.getByName("127.0.0.4");

        // The no-operation authenticator accepts every signature, so no key exchange over the network is required.
        this.authenticationClient = new AuthenticationClient(this.authorizationAuthority,
                new NoOperationAuthenticator(), this.egress);
        this.seedVerifier(this.authorizationAuthority);
        this.seedVerifier(this.verificationAuthority);
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
        AccessDecision verification = new AccessDecision(pattern(), AccessDecision.Action.DENY, null,
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

        AccessDecision deviating = new AccessDecision(pattern(), AccessDecision.Action.DENY, null,
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

    //
    // Outgoing session initializations and the data frame that triggers them
    //

    @Test
    public void testHeldFrameIsForwardedAfterMatchingVerification() throws Exception {
        AuthorizationManager manager = this.createManager(null, this.verificationAuthority);
        AccessDecision decision = grant(pattern(), this.nextHop, 60);
        AccessDecisionMessage message = this.sessionInitialization(decision);

        // The data frame finds no decision, triggers an access request, and is held
        AtomicReference<Optional<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        // The session initialization is held until the verifying PDP confirmed it
        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        manager.processMessage(this.verification(grant(pattern(), this.nextHop, 60)));
        join(worker);
        join(frame);

        assertTrue(result.get().isPresent(), "The held frame must be forwarded once the decision is verified.");
        assertEquals(this.nextHop, result.get().get().getDestination());
    }

    @Test
    public void testHeldFrameIsDroppedAfterDeviatingVerification() throws Exception {
        AuthorizationManager manager = this.createManager(null, this.verificationAuthority);
        AccessDecisionMessage message = this.sessionInitialization(grant(pattern(), this.nextHop, 60));

        AtomicReference<Optional<PayloadExchangeMessage>> result = new AtomicReference<>();
        Thread frame = startThread(() -> result.set(manager.authorizeOutgoing(packet())));
        assertInstanceOf(AccessRequestMessage.class, this.pollEgress());

        Thread worker = startThread(() -> manager.processMessage(message));
        assertInstanceOf(AccessVerificationRequestMessage.class, this.pollEgress());

        AccessDecision deviating = new AccessDecision(pattern(), AccessDecision.Action.DENY, null,
                Instant.now().plusSeconds(60));
        manager.processMessage(this.verification(deviating));
        join(worker);
        join(frame);

        assertTrue(result.get().isEmpty(), "The held frame must be dropped if the session initialization is unverifiable.");
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

    private AccessDecisionMessage sessionInitialization(AccessDecision decision) throws Exception {
        return new AccessDecisionMessage(this.authorizationAuthority, this.scope, null, decision)
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
