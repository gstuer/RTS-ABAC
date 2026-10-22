package com.gstuer.casc.common.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.StringAttribute;
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
import com.gstuer.casc.common.pattern.TcpPattern;
import com.gstuer.casc.common.pattern.UdpPattern;
import org.pcap4j.packet.Packet;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

public class JsonProcessor {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    private final Gson gson;

    public JsonProcessor() {
        this(false);
    }

    public JsonProcessor(boolean prettyPrinting) {
        GsonBuilder builder = new GsonBuilder();

        // Enable pretty printing for debugging purposes
        if (prettyPrinting) {
            builder.setPrettyPrinting();
        }

        // Register custom type adapters to serialize/deserialize objects correctly
        builder.registerTypeAdapter(Packet.class, new PacketSerializer());
        builder.registerTypeAdapter(Instant.class, new InstantSerializer());
        builder.registerTypeAdapter(Duration.class, new DurationSerializer());

        // Type factory for messages
        RuntimeTypeAdapterFactory<?> messageAdapterFactory = RuntimeTypeAdapterFactory
                .of(AccessControlMessage.class)
                .registerSubtype(PayloadExchangeMessage.class)
                .registerSubtype(KeyExchangeMessage.class)
                .registerSubtype(KeyExchangeRequestMessage.class)
                .registerSubtype(AccessRequestMessage.class)
                .registerSubtype(AccessDecisionMessage.class)
                .registerSubtype(AccessVerificationRequestMessage.class)
                .registerSubtype(AccessVerificationMessage.class)
                .registerSubtype(AttributeExchangeMessage.class)
                .registerSubtype(AttributeExchangeRequestMessage.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(messageAdapterFactory);

        // Type factory for flow patterns
        RuntimeTypeAdapterFactory<?> patternAdapterFactory = RuntimeTypeAdapterFactory
                .of(AccessRequestPattern.class)
                .registerSubtype(EthernetPattern.class)
                .registerSubtype(IpPattern.class)
                .registerSubtype(UdpPattern.class)
                .registerSubtype(TcpPattern.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(patternAdapterFactory);

        // Type factory for attributes
        RuntimeTypeAdapterFactory<?> attributeAdapterFactory = RuntimeTypeAdapterFactory
                .of(PolicyAttribute.class)
                .registerSubtype(LongAttribute.class)
                .registerSubtype(StringAttribute.class)
                .recognizeSubtypes();
        builder.registerTypeAdapterFactory(attributeAdapterFactory);
        this.gson = builder.create();
    }

    public static Charset getDefaultCharset() {
        return DEFAULT_CHARSET;
    }

    public String convertToJson(Object object) throws SerializationException {
        try {
            return this.gson.toJson(object);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
        }
    }

    public <T> T convertToObject(String json, Class<T> objectClass) throws SerializationException {
        try {
            return this.gson.fromJson(json, objectClass);
        } catch (JsonParseException exception) {
            throw new SerializationException(exception);
        }
    }

    public byte[] serialize(Object object) throws SerializationException {
        String json = convertToJson(object);
        return json.getBytes(DEFAULT_CHARSET);
    }

    public <T> T deserialize(byte[] object, Class<T> objectClass) throws SerializationException {
        String json = new String(object, DEFAULT_CHARSET);
        return this.convertToObject(json, objectClass);
    }
}
