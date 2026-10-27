package com.gstuer.casc.aasp.attribute;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.cryptography.NoOperationAuthenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.LongStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AttributePublisherTest {
    @Test
    public void testUpdaterTiming() throws UnknownHostException, InterruptedException {
        // Test Setup
        Duration validityDuration = Duration.ofMillis(50);
        InetAddress address = InetAddress.getByName("127.0.0.1");
        BlockingQueue<AccessControlMessage<?>> messageEgress = new LinkedBlockingQueue<>();
        AuthenticationClient authenticationClient = new AuthenticationClient(address, new NoOperationAuthenticator(), messageEgress);
        AttributePublisher publisher = new AttributePublisher(authenticationClient, messageEgress);
        InetAddress provider = InetAddress.getByName("127.0.0.1");
        Iterator<Long> longIterator = LongStream.iterate(0, i -> i + 1).iterator();
        LongAttribute attribute = new LongAttribute(new AttributeIdentifier("ID", provider),
                Instant.now(), validityDuration, longIterator::next);

        // Test Execution
        assertEquals(0L, attribute.getValue());
        publisher.publish(attribute);
        assertEquals(0L, attribute.getValue());
        Thread.sleep(validityDuration.toMillis());
        assertEquals(1L, attribute.getValue());
        Thread.sleep(validityDuration.toMillis());
        assertEquals(2L, attribute.getValue());
        Thread.sleep(validityDuration.toMillis());
        assertEquals(3L, attribute.getValue());
        Thread.sleep(validityDuration.toMillis());
        assertEquals(4L, attribute.getValue());
    }

    @Test
    public void testUnpublish() throws UnknownHostException, InterruptedException {
        // Test Setup
        Duration validityDuration = Duration.ofMillis(50);
        InetAddress address = InetAddress.getByName("127.0.0.1");
        BlockingQueue<AccessControlMessage<?>> messageEgress = new LinkedBlockingQueue<>();
        AuthenticationClient authenticationClient = new AuthenticationClient(address, new NoOperationAuthenticator(), messageEgress);
        AttributePublisher publisher = new AttributePublisher(authenticationClient, messageEgress);
        InetAddress provider = InetAddress.getByName("127.0.0.1");
        Iterator<Long> longIterator = LongStream.iterate(0, i -> i + 1).iterator();
        LongAttribute attribute = new LongAttribute(new AttributeIdentifier("ID", provider),
                Instant.now(), validityDuration, longIterator::next);

        // Test Execution
        publisher.publish(attribute);
        assertEquals(0L, attribute.getValue());
        Thread.sleep(validityDuration.toMillis());
        assertEquals(1L, attribute.getValue());
        publisher.unpublish(attribute);
        Thread.sleep(2 * validityDuration.toMillis());
        assertEquals(1L, attribute.getValue());
    }
}
