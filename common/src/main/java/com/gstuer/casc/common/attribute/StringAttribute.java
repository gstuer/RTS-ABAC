package com.gstuer.casc.common.attribute;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * A {@link PolicyAttribute policy attribute} whose value is a character sequence, e.g. an operational state or the
 * identifier of a system component.
 */
public class StringAttribute extends PolicyAttribute<String> {
    /**
     * The identifier by which this attribute type is referred to in the attribute configuration of an AASP.
     */
    public static final String TYPE_IDENTIFIER = "StringAttribute";

    @Serial
    private static final long serialVersionUID = 132124938264322981L;

    public StringAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, String value) {
        super(identifier, validFrom, validityDuration, value);
    }

    public StringAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Supplier<String> valueSupplier) {
        super(identifier, validFrom, validityDuration, valueSupplier);
    }

    /**
     * Creates an attribute whose value is parsed from the data of an attribute source on every refresh, so that the
     * published value follows the source without the source having to know the value type.
     *
     * @param identifier       the identifier of the attribute
     * @param validityDuration the period for which each published value is valid
     * @param dataSupplier     the supplier of the raw data of the attribute source
     * @return the attribute, whose value is the parsed data of the source.
     */
    public static StringAttribute createFromData(AttributeIdentifier identifier, Duration validityDuration,
                                                 Supplier<String> dataSupplier) {
        return new StringAttribute(identifier, Instant.now(), validityDuration,
                () -> parseValue(dataSupplier.get()));
    }

    /**
     * Parses the value of this attribute type from the data of an attribute source. The data of a character sequence
     * is stripped of surrounding whitespace, so that a value read from a file is independent of a trailing newline.
     *
     * @param data the raw data of the attribute source
     * @return the parsed attribute value.
     */
    public static String parseValue(String data) {
        return data.strip();
    }

    @Override
    public byte[] getValueAsBytes() {
        return this.getValue().getBytes();
    }
}
