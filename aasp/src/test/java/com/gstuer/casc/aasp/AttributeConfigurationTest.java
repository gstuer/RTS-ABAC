package com.gstuer.casc.aasp;

import com.google.gson.JsonParser;
import com.gstuer.casc.aasp.AttributeConfiguration.AttributeDefinition;
import com.gstuer.casc.aasp.source.AttributeSource;
import com.gstuer.casc.aasp.source.AttributeSourceFactory;
import com.gstuer.casc.aasp.source.ConstantAttributeSource;
import com.gstuer.casc.aasp.source.FileAttributeSource;
import com.gstuer.casc.aasp.attribute.AttributeFactory;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.StringAttribute;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the attribute configuration of an AASP, i.e. the JSON document that states which attributes the AASP
 * publishes, of which type, for which period of validity, and from which source.
 */
public class AttributeConfigurationTest {
    private static final String CONFIGURATION = """
            {
              "attributes": [
                {
                  "name": "intruded",
                  "type": "LongAttribute",
                  "validity": "PT5S",
                  "source": {"type": "file", "path": "%s"}
                },
                {
                  "name": "operationalState",
                  "type": "StringAttribute",
                  "validity": "PT30S",
                  "source": {"type": "constant", "value": "normal"}
                }
              ]
            }
            """;

    /**
     * The configuration states the name, the type, the period of validity, and the source of every attribute an AASP
     * publishes. The period of validity is also the polling rate of the attribute, as an AASP vouches for a value
     * for that period only.
     */
    @Test
    public void testConfigurationOfSeveralAttributesIsRead(@TempDir Path directory) throws IOException {
        Path configurationPath = writeConfiguration(directory, "1");

        AttributeConfiguration configuration = AttributeConfiguration.readFrom(configurationPath);

        assertEquals(2, configuration.attributes().size());
        AttributeDefinition intruded = configuration.attributes().get(0);
        assertEquals("intruded", intruded.name());
        assertEquals(LongAttribute.TYPE_IDENTIFIER, intruded.type());
        assertEquals(Duration.ofSeconds(5), intruded.validity());
        assertEquals(FileAttributeSource.TYPE_IDENTIFIER, intruded.source().get("type").getAsString());
        AttributeDefinition state = configuration.attributes().get(1);
        assertEquals(Duration.ofSeconds(30), state.validity());
        assertEquals(StringAttribute.TYPE_IDENTIFIER, state.type());
    }

    /**
     * An incomplete configuration is rejected with a message naming the attribute at fault, as an AASP that
     * published an attribute it cannot refresh would let the PDPs evaluate policies against a value nobody vouches
     * for.
     */
    @Test
    public void testIncompleteConfigurationIsRejected(@TempDir Path directory) throws IOException {
        Path path = directory.resolve("attributes.json");
        Files.writeString(path, """
                {"attributes": [{"name": "intruded", "validity": "PT5S", "source": {"type": "constant"}}]}
                """);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> AttributeConfiguration.readFrom(path));
        assertTrue(exception.getMessage().contains("intruded"), "The attribute at fault has to be named.");
    }

    /**
     * A document that states no attributes at all is rejected as well, rather than starting an AASP that serves
     * nothing.
     */
    @Test
    public void testConfigurationWithoutAttributesIsRejected(@TempDir Path directory) throws IOException {
        Path path = directory.resolve("attributes.json");
        Files.writeString(path, "{}");

        assertThrows(IllegalArgumentException.class, () -> AttributeConfiguration.readFrom(path));
    }

    /**
     * The kind of source is selected by the {@code type} member of the source object, whose further members
     * configure that kind. A source whose configuration is incomplete is rejected.
     */
    @Test
    public void testSourcesAreCreatedFromTheirConfiguration(@TempDir Path directory) throws IOException {
        Path valuePath = directory.resolve("intruded");
        Files.writeString(valuePath, "1");
        AttributeConfiguration configuration = AttributeConfiguration.readFrom(writeConfiguration(directory, "1"));

        AttributeSource fileSource = AttributeSourceFactory
                .createBySourceType(configuration.attributes().get(0).source()).orElseThrow();
        AttributeSource constantSource = AttributeSourceFactory
                .createBySourceType(configuration.attributes().get(1).source()).orElseThrow();

        assertInstanceOf(FileAttributeSource.class, fileSource);
        assertEquals(valuePath, ((FileAttributeSource) fileSource).getPath());
        assertEquals("1", fileSource.readData().strip());
        assertInstanceOf(ConstantAttributeSource.class, constantSource);
        assertEquals("normal", constantSource.readData());
    }

    /**
     * An attribute follows its source: the published value is parsed from the data of the source on every refresh,
     * and the parsing is a task of the attribute type rather than of the source.
     */
    @Test
    public void testAttributeFollowsTheDataOfItsSource(@TempDir Path directory) throws IOException {
        Path valuePath = directory.resolve("intruded");
        Files.writeString(valuePath, "0\n");
        AttributeIdentifier identifier = new AttributeIdentifier("intruded", InetAddress.getByName("127.0.0.1"));
        AttributeSource source = new FileAttributeSource(valuePath);

        PolicyAttribute<?> attribute = AttributeFactory.createByTypeIdentifier(LongAttribute.TYPE_IDENTIFIER,
                identifier, Duration.ofSeconds(5), source).orElseThrow();

        assertEquals(0L, attribute.getValue(), "A trailing newline must not keep the data from being parsed.");
        Files.writeString(valuePath, "1");
        attribute.update();
        assertEquals(1L, attribute.getValue(), "The refreshed value is the current data of the source.");
    }

    /**
     * An unknown attribute type and an unknown kind of source are reported rather than ignored, so that a
     * misconfigured AASP does not start up serving an incomplete set of attributes.
     */
    @Test
    public void testUnknownTypeAndUnknownSourceAreReported() throws IOException {
        AttributeIdentifier identifier = new AttributeIdentifier("intruded", InetAddress.getByName("127.0.0.1"));

        assertTrue(AttributeFactory.createByTypeIdentifier("BooleanAttribute", identifier, Duration.ofSeconds(5),
                () -> "1").isEmpty());
        assertTrue(AttributeSourceFactory.createBySourceType(
                JsonParser.parseString("{\"type\": \"rest\"}").getAsJsonObject()).isEmpty());
    }

    /**
     * The data of a source that cannot be read is no attribute value: the source reports the failure, so that the
     * attribute expires instead of a stale value being published.
     */
    @Test
    public void testUnreadableFileSourceReportsFailure(@TempDir Path directory) {
        AttributeSource source = new FileAttributeSource(directory.resolve("absent"));

        assertThrows(IllegalStateException.class, source::readData);
    }

    private static Path writeConfiguration(Path directory, String value) throws IOException {
        Path valuePath = directory.resolve("intruded");
        Files.writeString(valuePath, value);
        Path configurationPath = directory.resolve("attributes.json");
        Files.writeString(configurationPath, CONFIGURATION.formatted(valuePath.toString()));
        return configurationPath;
    }
}
