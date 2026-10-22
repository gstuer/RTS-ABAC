package com.gstuer.casc.pep;

import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.egress.AccessControlMessageEgressHandler;
import com.gstuer.casc.common.egress.PacketEgressHandler;
import com.gstuer.casc.common.ingress.AccessControlMessageIngressHandler;
import com.gstuer.casc.common.ingress.PacketIngressHandler;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.pep.access.AccessController;
import com.gstuer.casc.pep.predicate.PacketPredicate;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

public class NetworkBridge {
    private static final int UDP_PORT_INCOMING = 10000;
    private static final int UDP_PORT_OUTGOING = 10001;

    private final PcapNetworkInterface networkInterfaceInsecure;
    private final PcapNetworkInterface networkInterfaceSecure;
    private final InetAddress authorizationAuthority;
    private final InetAddress incomingVerificationAuthority;
    private final InetAddress outgoingVerificationAuthority;
    private final InetAddress authenticationAuthority;
    private final Authenticator<?, ?> authenticator;
    private final BlockingQueue<Packet> egressQueueInsecure;
    private final BlockingQueue<Packet> egressQueueSecure;
    private final BlockingQueue<AccessControlMessage<?>> egressQueueMessage;
    private final PacketPredicate bypassPredicate;

    private PacketEgressHandler egressHandlerInsecure;
    private PacketEgressHandler egressHandlerSecure;
    private AccessControlMessageEgressHandler egressHandlerMessage;
    private PacketIngressHandler ingressHandlerInsecure;
    private PacketIngressHandler ingressHandlerSecure;
    private AccessControlMessageIngressHandler ingressHandlerMessage;
    private AccessController accessController;
    private ExecutorService threadPool;

    public NetworkBridge(PcapNetworkInterface networkInterfaceInsecure, PcapNetworkInterface networkInterfaceSecure,
                         InetAddress authorizationAuthority, InetAddress authenticationAuthority,
                         Authenticator<?, ?> authenticator, PacketPredicate... bypassPredicates) {
        this(networkInterfaceInsecure, networkInterfaceSecure, authorizationAuthority, null, null,
                authenticationAuthority, authenticator, bypassPredicates);
    }

    /**
     * Constructs a new {@link NetworkBridge network bridge}.
     *
     * @param networkInterfaceInsecure      the interface facing the network shared with the other PEPs
     * @param networkInterfaceSecure        the interface facing the protected SAS device
     * @param authorizationAuthority        the address of the PDP that issues the session initializations
     * @param incomingVerificationAuthority the address of the PDP against which session initializations for incoming
     *                                      traffic are verified, or {@code null} to accept them unverified
     * @param outgoingVerificationAuthority the address of the PDP against which session initializations for outgoing
     *                                      traffic are verified, or {@code null} to accept them unverified
     * @param authenticationAuthority       the address of the authentication authority
     * @param authenticator                 the authenticator used to sign and verify access control messages
     * @param bypassPredicates              predicates selecting the traffic forwarded without access control
     */
    public NetworkBridge(PcapNetworkInterface networkInterfaceInsecure, PcapNetworkInterface networkInterfaceSecure,
                         InetAddress authorizationAuthority, InetAddress incomingVerificationAuthority,
                         InetAddress outgoingVerificationAuthority, InetAddress authenticationAuthority,
                         Authenticator<?, ?> authenticator, PacketPredicate... bypassPredicates) {
        this.networkInterfaceInsecure = Objects.requireNonNull(networkInterfaceInsecure);
        this.networkInterfaceSecure = Objects.requireNonNull(networkInterfaceSecure);

        this.authorizationAuthority = Objects.requireNonNull(authorizationAuthority);
        this.incomingVerificationAuthority = incomingVerificationAuthority;
        this.outgoingVerificationAuthority = outgoingVerificationAuthority;
        this.authenticationAuthority = Objects.requireNonNull(authenticationAuthority);
        this.authenticator = Objects.requireNonNull(authenticator);

        this.egressQueueInsecure = new LinkedBlockingQueue<>();
        this.egressQueueSecure = new LinkedBlockingQueue<>();
        this.egressQueueMessage = new LinkedBlockingQueue<>();

        // Compose predicates for traffic bypass to single predicate
        PacketPredicate composedPredicate = PacketPredicate.getStaticPredicate(false);
        for (PacketPredicate bypassPredicate : bypassPredicates) {
            composedPredicate = composedPredicate.or(bypassPredicate);
        }
        this.bypassPredicate = composedPredicate;
    }

    public void open() {
        // If bridge is already open, ignore method call
        if ((this.egressHandlerInsecure != null || this.egressHandlerSecure != null
                || this.ingressHandlerInsecure != null || this.ingressHandlerSecure != null)
                && !this.threadPool.isTerminated()) {
            return;
        }

        // Clear egress queues of previously opened bridge
        this.egressQueueInsecure.clear();
        this.egressQueueSecure.clear();
        this.egressQueueMessage.clear();

        // Initialize access controller
        List<PcapAddress> insecureAddresses = this.networkInterfaceInsecure.getAddresses();
        if (insecureAddresses.isEmpty()) {
            throw new IllegalStateException("Insecure network interface has no IP address.");
        }
        InetAddress authorizationScope = insecureAddresses.get(0).getAddress();
        this.accessController = new AccessController(this.egressQueueMessage, this.egressQueueSecure,
                this.authorizationAuthority, authorizationScope, this.incomingVerificationAuthority,
                this.outgoingVerificationAuthority, this.authenticationAuthority, authenticator);

        // Specify ingress packet consumers
        Consumer<Packet> egressEnqueueInsecure = this.egressQueueInsecure::offer;
        Consumer<Packet> egressEnqueueSecure = this.egressQueueSecure::offer;
        Consumer<Packet> packetConsumerInsecure = (packet) -> bypassPredicate.doIfMatches(packet, egressEnqueueSecure);
        Consumer<Packet> packetConsumerSecure = (packet) -> bypassPredicate.doIfMatchesOrElse(packet,
                egressEnqueueInsecure, this.accessController::handleOutgoingRequest);

        // Construct ingress and egress handlers
        try {
            // Egress handler
            this.egressHandlerMessage = new AccessControlMessageEgressHandler(UDP_PORT_OUTGOING, UDP_PORT_INCOMING, this.egressQueueMessage);
            this.egressHandlerInsecure = new PacketEgressHandler(this.networkInterfaceInsecure, this.egressQueueInsecure);
            this.egressHandlerSecure = new PacketEgressHandler(this.networkInterfaceSecure, this.egressQueueSecure);

            // Ingress handler
            this.ingressHandlerMessage = new AccessControlMessageIngressHandler(UDP_PORT_INCOMING, this.accessController::handleIncomingRequest);
            this.ingressHandlerInsecure = new PacketIngressHandler(this.networkInterfaceInsecure, packetConsumerInsecure);
            this.ingressHandlerSecure = new PacketIngressHandler(this.networkInterfaceSecure, packetConsumerSecure);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }

        // Start handler threads
        this.threadPool = Executors.newFixedThreadPool(6);
        this.threadPool.submit(this.egressHandlerMessage::open);
        this.threadPool.submit(this.egressHandlerInsecure::open);
        this.threadPool.submit(this.egressHandlerSecure::open);
        this.threadPool.submit(this.ingressHandlerMessage::open);
        this.threadPool.submit(this.ingressHandlerInsecure::open);
        this.threadPool.submit(this.ingressHandlerSecure::open);
    }

    public void close() {
        this.ingressHandlerInsecure.close();
        this.ingressHandlerSecure.close();
        this.ingressHandlerMessage.close();
        this.egressHandlerInsecure.close();
        this.egressHandlerSecure.close();
        this.egressHandlerMessage.close();
        this.threadPool.shutdownNow();
    }
}
