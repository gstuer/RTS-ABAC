package com.gstuer.casc.aasp.attribute;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.LongAttribute;
import com.gstuer.casc.common.attribute.StringAttribute;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * A utility class for the creation of {@link PolicyAttribute policy attribute} instances from the attribute
 * configuration of an AASP, which states the type of an attribute by its type identifier.
 */
public final class AttributeFactory {
    private AttributeFactory() {
        throw new AssertionError("No instances of this utility class allowed.");
    }

    /**
     * Creates an attribute of the given type, whose value is parsed from the data of an attribute source on every
     * refresh. The parsing is a task of the attribute type, so that an attribute source provides raw data and needs
     * no knowledge of the value type it serves.
     *
     * @param typeIdentifier   the type identifier of the attribute to be created
     * @param identifier       the identifier of the attribute
     * @param validityDuration the period for which each published value is valid
     * @param dataSupplier     the supplier of the raw data of the attribute source
     * @return the created attribute, or an empty optional if the type identifier is unknown.
     */
    public static Optional<PolicyAttribute<?>> createByTypeIdentifier(String typeIdentifier,
                                                                      AttributeIdentifier identifier,
                                                                      Duration validityDuration,
                                                                      Supplier<String> dataSupplier) {
        PolicyAttribute<?> attribute = null;
        if (LongAttribute.TYPE_IDENTIFIER.equals(typeIdentifier)) {
            attribute = LongAttribute.createFromData(identifier, validityDuration, dataSupplier);
        } else if (StringAttribute.TYPE_IDENTIFIER.equals(typeIdentifier)) {
            attribute = StringAttribute.createFromData(identifier, validityDuration, dataSupplier);
        }
        return Optional.ofNullable(attribute);
    }
}
