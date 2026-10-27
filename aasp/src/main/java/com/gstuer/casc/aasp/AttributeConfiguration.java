package com.gstuer.casc.aasp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.gstuer.casc.common.serialization.DurationSerializer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Represents the configuration of the attributes an AASP publishes, which is read from a JSON document at startup.
 * The document states, per attribute, its unique name, its type, the period of validity of each published value, and
 * the source the value is read from:
 * <pre>
 * {
 *   "attributes": [
 *     {
 *       "name": "intruded",
 *       "type": "LongAttribute",
 *       "validity": "PT5S",
 *       "source": {"type": "file", "path": "/home/pi/intruded"}
 *     },
 *     {
 *       "name": "operationalState",
 *       "type": "StringAttribute",
 *       "validity": "PT30S",
 *       "source": {"type": "constant", "value": "normal"}
 *     }
 *   ]
 * }
 * </pre>
 * The period of validity is also the polling rate, as the source of an attribute is read once per period: an AASP
 * vouches for a value for that period only, and a PDP bounds the validity of the access decisions it derives by it.
 * The source is a nested object whose {@code type} selects the kind of source and whose further members configure
 * that kind, so that further kinds of sources are added without changing the structure of the document.
 *
 * @param attributes the attributes to be published
 */
public record AttributeConfiguration(List<AttributeDefinition> attributes) {
    /**
     * Reads an attribute configuration from a JSON document.
     *
     * @param path the path of the JSON document
     * @return the attribute configuration stated by the document.
     * @throws IOException              if the document cannot be read
     * @throws IllegalArgumentException if the document is no valid attribute configuration
     */
    public static AttributeConfiguration readFrom(Path path) throws IOException {
        Gson gson = new GsonBuilder().registerTypeAdapter(Duration.class, new DurationSerializer()).create();
        AttributeConfiguration configuration;
        try {
            configuration = gson.fromJson(Files.readString(path, StandardCharsets.UTF_8),
                    AttributeConfiguration.class);
        } catch (JsonParseException exception) {
            throw new IllegalArgumentException("Attribute configuration is no valid JSON document: "
                    + exception.getMessage(), exception);
        }
        if (Objects.isNull(configuration) || Objects.isNull(configuration.attributes())) {
            throw new IllegalArgumentException("Attribute configuration states no attributes.");
        }
        configuration.attributes().forEach(AttributeDefinition::validate);
        return configuration;
    }

    /**
     * Represents the configuration of a single attribute published by an AASP.
     *
     * @param name     the name of the attribute, which identifies it together with the address of this AASP
     * @param type     the type identifier of the attribute, which also determines how its source data is parsed
     * @param validity the period for which each published value is valid, which is also its polling rate
     * @param source   the configuration of the source the attribute value is read from
     */
    public record AttributeDefinition(String name, String type, Duration validity, JsonObject source) {
        /**
         * Validates that this definition states everything required to publish the attribute.
         *
         * @throws IllegalArgumentException if a member is missing or not usable
         */
        private void validate() {
            if (Objects.isNull(this.name) || this.name.isBlank()) {
                throw new IllegalArgumentException("An attribute of the configuration states no name.");
            }
            if (Objects.isNull(this.type) || this.type.isBlank()) {
                throw new IllegalArgumentException("Attribute \"" + this.name + "\" states no type.");
            }
            if (Objects.isNull(this.validity) || this.validity.isNegative() || this.validity.isZero()) {
                throw new IllegalArgumentException("Attribute \"" + this.name
                        + "\" states no positive period of validity.");
            }
            if (Objects.isNull(this.source)) {
                throw new IllegalArgumentException("Attribute \"" + this.name + "\" states no source.");
            }
        }
    }
}
