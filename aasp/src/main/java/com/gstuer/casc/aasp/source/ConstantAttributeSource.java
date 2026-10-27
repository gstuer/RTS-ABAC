package com.gstuer.casc.aasp.source;

import java.util.Objects;

/**
 * An {@link AttributeSource attribute source} of a constant value, i.e. of a system property that the operator
 * configures rather than one that an external system reports. The attribute is nevertheless republished once per
 * period of validity, as an AASP vouches for a value only for that period.
 */
public class ConstantAttributeSource implements AttributeSource {
    /**
     * The identifier by which this source type is referred to in the attribute configuration of an AASP.
     */
    public static final String TYPE_IDENTIFIER = "constant";

    private final String data;

    /**
     * Constructs a new {@link ConstantAttributeSource constant attribute source}.
     *
     * @param data the raw data of the constant attribute value
     */
    public ConstantAttributeSource(String data) {
        this.data = Objects.requireNonNull(data);
    }

    @Override
    public String readData() {
        return this.data;
    }
}
