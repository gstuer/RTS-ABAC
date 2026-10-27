package com.gstuer.casc.aasp.source;

import java.util.function.Supplier;

/**
 * Represents the origin of the value of an attribute published by an AASP, e.g. a file written by an intrusion
 * detection system or a constant configured by the operator.
 * <p>
 * A source provides the raw data of an attribute and has no knowledge of the value type served: the parsing of the
 * data is a task of the {@link com.gstuer.casc.common.attribute.PolicyAttribute attribute type}, so that every
 * source can serve every attribute type. A source is read once per period of validity of the attribute, i.e. the
 * polling rate of the attribute is its period of validity.
 */
public interface AttributeSource extends Supplier<String> {
    /**
     * Reads the current raw data of this source.
     *
     * @return the raw data of the attribute value.
     * @throws IllegalStateException if the data is momentarily unavailable, which lets the attribute expire rather
     *                               than publishing a value this AASP no longer vouches for
     */
    String readData();

    @Override
    default String get() {
        return this.readData();
    }
}
