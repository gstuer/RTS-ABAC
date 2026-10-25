package com.gstuer.casc.common.serialization;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.StringAttribute;
import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.message.AccessVerificationMessage;
import com.gstuer.casc.common.message.AccessVerificationRequestMessage;
import com.gstuer.casc.common.message.AttributeExchangeMessage;
import com.gstuer.casc.common.message.AttributeExchangeRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import com.gstuer.casc.common.pattern.IpPattern;
import com.gstuer.casc.common.pattern.PatternFactory;
import com.gstuer.casc.common.pattern.UdpPattern;
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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class JsonProcessorTest {
    @Test
    public void testSerializationAndDeserializationOfPayloadExchangeMessage() throws UnknownHostException, SerializationException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        Packet packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.ARP)
                .paddingAtBuild(true)
                .build();
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        PayloadExchangeMessage message = new PayloadExchangeMessage(source, destination, signature, packet);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        PayloadExchangeMessage deserialMessage = (PayloadExchangeMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfKeyExchangeRequestMessageWithSignature() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        String algorithmIdentifier = "ALGORITHM";
        KeyExchangeRequestMessage message = new KeyExchangeRequestMessage(source, destination, signature, algorithmIdentifier);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        KeyExchangeRequestMessage deserialMessage = (KeyExchangeRequestMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfKeyExchangeRequestMessageWithoutSignature() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        String algorithmIdentifier = "ALGORITHM";
        KeyExchangeRequestMessage message = new KeyExchangeRequestMessage(source, destination, null, algorithmIdentifier);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        KeyExchangeRequestMessage deserialMessage = (KeyExchangeRequestMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfKeyExchangeMessage() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        EncodedKey encodedKey = new EncodedKey("ALGORITHM", new byte[32]);
        KeyExchangeMessage message = new KeyExchangeMessage(source, destination, signature, encodedKey);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        KeyExchangeMessage deserialMessage = (KeyExchangeMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfAccessRequestPattern() throws UnknownHostException, SerializationException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        EthernetPacket packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
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
                                .dstPort(new UdpPort((short) 10000, "SABAAC"))
                        ))
                .build();

        // Execution
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(packet);
        byte[] serialPattern = jsonProcessor.serialize(pattern);
        UdpPattern udpPattern = (UdpPattern) jsonProcessor.deserialize(serialPattern, AccessRequestPattern.class);
        IpPattern ipPattern = (IpPattern) udpPattern.getEnclosedPattern();
        EthernetPattern ethernetPattern = (EthernetPattern) ipPattern.getEnclosedPattern();

        // Assertion
        assertEquals(pattern, udpPattern);
        assertTrue(udpPattern.equalsIsolated(pattern));
        assertTrue(ipPattern.equalsIsolated(pattern.getEnclosedPattern()));
        assertTrue(ethernetPattern.equalsIsolated(pattern.getEnclosedPattern().getEnclosedPattern()));
    }

    @Test
    public void testSerializationAndDeserializationOfAccessDecision() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessRequestPattern pattern = new UdpPattern(10000, 10001, null);
        InetAddress address = InetAddress.getByName("127.0.0.1");
        AccessDecision.Action action = AccessDecision.Action.GRANT;
        Instant validUntilNow = Instant.now();
        AccessDecision accessDecision = new AccessDecision(pattern, action, address, validUntilNow);

        // Execution
        byte[] serial = jsonProcessor.serialize(accessDecision);
        AccessDecision deserialized = jsonProcessor.deserialize(serial, AccessDecision.class);

        // Assertion
        assertNotNull(deserialized);
        assertEquals(pattern, deserialized.getPattern());
        assertEquals(Set.of(address), deserialized.getNextHops());
        assertEquals(action, deserialized.getAction());
        assertEquals(validUntilNow, deserialized.getValidUntil());
    }

    /**
     * A session initialization transmits one or multiple access decisions, each of which may permit several
     * recipients and may state that its policy is not applicable. The wire format has to preserve all of it, as a
     * PEP resolves the transmitted decisions for the individual data frame.
     */
    @Test
    public void testSerializationAndDeserializationOfSessionInitializationWithSeveralDecisions()
            throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessRequestPattern pattern = new UdpPattern(10000, 10001, null);
        InetAddress firstNextHop = InetAddress.getByName("127.0.0.1");
        InetAddress secondNextHop = InetAddress.getByName("127.0.0.2");
        Instant validUntil = Instant.now();
        AccessDecision grant = new AccessDecision(pattern, AccessDecision.Action.GRANT,
                Set.of(firstNextHop, secondNextHop), validUntil);
        AccessDecision nonApplicable = new AccessDecision(pattern, AccessDecision.Action.NOTAPPLICABLE, Set.of(),
                validUntil);
        DigitalSignature signature = new DigitalSignature(new byte[]{1, 2, 3, 4}, "test");
        AccessDecisionMessage message = new AccessDecisionMessage(firstNextHop, signature,
                List.of(grant, nonApplicable));

        // Execution
        byte[] serial = jsonProcessor.serialize(message);
        AccessDecisionMessage deserialized = (AccessDecisionMessage) jsonProcessor.deserialize(serial,
                AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialized);
        assertEquals(message, deserialized);
        assertEquals(2, deserialized.getPayload().size());
        assertEquals(Set.of(firstNextHop, secondNextHop), deserialized.getPayload().get(0).getNextHops());
        assertFalse(deserialized.getPayload().get(1).isApplicable());
        assertArrayEquals(message.getSigningData(), deserialized.getSigningData(),
                "The signing data has to be reproducible from the deserialized message.");
    }

    @Test
    public void testSerializationAndDeserializationOfAccessDecisionMessage() throws SerializationException, UnknownHostException {
        // Test data
        //// Construct access decision
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessRequestPattern pattern = new UdpPattern(10000, 10001, null);
        InetAddress address = InetAddress.getByName("127.0.0.1");
        AccessDecision.Action action = AccessDecision.Action.GRANT;
        Instant validUntilNow = Instant.now();
        AccessDecision accessDecision = new AccessDecision(pattern, action, address, validUntilNow);

        //// Construct message
        DigitalSignature signature = new DigitalSignature(new byte[]{1, 2, 3, 4}, "test");
        AccessDecisionMessage message = new AccessDecisionMessage(address, signature, accessDecision);

        // Execution
        byte[] serial = jsonProcessor.serialize(message);
        AccessDecisionMessage deserialized = (AccessDecisionMessage) jsonProcessor.deserialize(serial, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialized);
        assertEquals(message, deserialized);
    }

    @Test
    public void testSerializationAndDeserializationOfAccessRequestMessage() throws SerializationException, UnknownHostException {
        // Test data
        //// Construct access decision
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessRequestPattern pattern = new UdpPattern(10000, 10001, null);
        InetAddress address = InetAddress.getByName("127.0.0.1");

        //// Construct message
        DigitalSignature signature = new DigitalSignature(new byte[]{1, 2, 3, 4}, "test");
        AccessRequestMessage message = new AccessRequestMessage(address, signature, pattern);

        // Execution
        byte[] serial = jsonProcessor.serialize(message);
        AccessRequestMessage deserialized = (AccessRequestMessage) jsonProcessor.deserialize(serial, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialized);
        assertEquals(message, deserialized);
    }

    @Test
    public void testSerializationAndDeserializationOfAttributeExchangeRequestMessage() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        Set<AttributeIdentifier> attributeIdentifiers = Set.of(
                new AttributeIdentifier("ID_1", source),
                new AttributeIdentifier("ID_2", source),
                new AttributeIdentifier("ID_3", source)
        );
        AttributeExchangeRequestMessage message = new AttributeExchangeRequestMessage(source, destination, signature, attributeIdentifiers);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        AttributeExchangeRequestMessage deserialMessage = (AttributeExchangeRequestMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfAttributeExchangeMessage() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");

        Instant now = Instant.now();
        Set<PolicyAttribute<?>> attributes = Set.of(
                new LongAttribute(new AttributeIdentifier("Long 1", source), now, Duration.ofSeconds(60), 1234L),
                new LongAttribute(new AttributeIdentifier("Long 2", source), now, Duration.ofSeconds(100), 5678L),
                new StringAttribute(new AttributeIdentifier("String 1", source), now, Duration.ofSeconds(60), "String"),
                new LongAttribute(new AttributeIdentifier("Long 3", source), now, Duration.ofSeconds(0), 0L)
        );
        AttributeExchangeMessage message = new AttributeExchangeMessage(source, destination, signature, attributes);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        AttributeExchangeMessage deserialMessage = (AttributeExchangeMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfAccessVerificationRequestMessage() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        AccessRequestPattern pattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        AccessVerificationRequestMessage message = new AccessVerificationRequestMessage(source, destination, signature, pattern);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        AccessControlMessage<?> deserialMessage = jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertions
        assertNotNull(deserialMessage);
        assertInstanceOf(AccessVerificationRequestMessage.class, deserialMessage);
        assertEquals(message, deserialMessage);
    }

    @Test
    public void testSerializationAndDeserializationOfAccessVerificationMessage() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        InetAddress nextHop = InetAddress.getByName("127.0.0.4");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        AccessRequestPattern pattern = new EthernetPattern(MacAddress.getByName("00:00:00:00:00:00"),
                MacAddress.getByName("ff:ff:ff:ff:ff:ff"), EtherType.IPV4);
        AccessDecision decision = new AccessDecision(pattern, AccessDecision.Action.GRANT, nextHop,
                Instant.now().plus(Duration.ofSeconds(60)));
        AccessVerificationMessage message = new AccessVerificationMessage(source, destination, signature, decision);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        AccessControlMessage<?> deserialMessage = jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertions
        assertNotNull(deserialMessage);
        assertInstanceOf(AccessVerificationMessage.class, deserialMessage);
        assertEquals(message, deserialMessage);
    }
}
