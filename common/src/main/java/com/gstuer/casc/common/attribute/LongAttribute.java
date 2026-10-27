package com.gstuer.casc.common.attribute;

import com.google.common.primitives.Longs;

import java.io.Serial;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * A {@link PolicyAttribute policy attribute} whose value is an integral number, e.g. a counter, a measurement, or a
 * flag that an AASP publishes as zero or one.
 */
public class LongAttribute extends PolicyAttribute<Long> {
    /**
     * The identifier by which this attribute type is referred to in the attribute configuration of an AASP.
     */
    public static final String TYPE_IDENTIFIER = "LongAttribute";

    @Serial
    private static final long serialVersionUID = -2625075482404930676L;

    public LongAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Long value) {
        super(identifier, validFrom, validityDuration, value);
    }

    public LongAttribute(AttributeIdentifier identifier, Instant validFrom, Duration validityDuration, Supplier<Long> valueSupplier) {
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
    public static LongAttribute createFromData(AttributeIdentifier identifier, Duration validityDuration,
                                               Supplier<String> dataSupplier) {
        return new LongAttribute(identifier, Instant.now(), validityDuration,
                () -> parseValue(dataSupplier.get()));
    }

    /**
     * Parses the value of this attribute type from the data of an attribute source.
     *
     * @param data the raw data of the attribute source
     * @return the parsed attribute value.
     * @throws IllegalArgumentException if the data does not represent an integral number
     */
    public static Long parseValue(String data) {
        try {
            return Long.parseLong(data.strip());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Attribute data is no integral number: " + data.strip(), exception);
        }
    }

    @Override
    public byte[] getValueAsBytes() {
        return Longs.toByteArray(this.getValue());
    }
}
