package com.gstuer.casc.aasp.source;

import com.google.gson.JsonObject;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * A utility class for the creation of {@link AttributeSource attribute source} instances from the source object of an
 * attribute configuration. The {@code type} member of that object selects the kind of source, and its further
 * members configure the selected kind, so that a further kind of source is added here without changing the structure
 * of an attribute configuration.
 */
public final class AttributeSourceFactory {
    private static final String TYPE_MEMBER = "type";

    private AttributeSourceFactory() {
        throw new AssertionError("No instances of this utility class allowed.");
    }

    /**
     * Creates the attribute source configured by the source object of an attribute configuration.
     *
     * @param source the source object of an attribute configuration
     * @return the configured attribute source, or an empty optional if the stated kind of source is unknown.
     * @throws IllegalArgumentException if the source object does not configure the stated kind of source completely
     */
    public static Optional<AttributeSource> createBySourceType(JsonObject source) {
        String type = getMember(source, TYPE_MEMBER);
        AttributeSource attributeSource = null;
        if (FileAttributeSource.TYPE_IDENTIFIER.equals(type)) {
            attributeSource = new FileAttributeSource(Path.of(getMember(source, "path")));
        } else if (ConstantAttributeSource.TYPE_IDENTIFIER.equals(type)) {
            attributeSource = new ConstantAttributeSource(getMember(source, "value"));
        }
        return Optional.ofNullable(attributeSource);
    }

    /**
     * Gets a member of a source object as a string.
     *
     * @param source the source object of an attribute configuration
     * @param member the name of the member to be read
     * @return the value of the member.
     * @throws IllegalArgumentException if the member is absent
     */
    private static String getMember(JsonObject source, String member) {
        if (!source.has(member) || Objects.isNull(source.get(member).getAsString())) {
            throw new IllegalArgumentException("Attribute source states no \"" + member + "\": " + source);
        }
        return source.get(member).getAsString();
    }
}
