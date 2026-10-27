package com.gstuer.casc.aasp.source;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * An {@link AttributeSource attribute source} that reads the value of an attribute from a file, which is the
 * interface through which an external system such as an intrusion detection system reports a system property to an
 * AASP. The file is read once per period of validity of the attribute, so that a value written to it becomes
 * effective within one such period.
 */
public class FileAttributeSource implements AttributeSource {
    /**
     * The identifier by which this source type is referred to in the attribute configuration of an AASP.
     */
    public static final String TYPE_IDENTIFIER = "file";

    private final Path path;

    /**
     * Constructs a new {@link FileAttributeSource file attribute source}.
     *
     * @param path the path of the file holding the attribute value
     */
    public FileAttributeSource(Path path) {
        this.path = Objects.requireNonNull(path);
    }

    public Path getPath() {
        return this.path;
    }

    @Override
    public String readData() {
        try {
            return Files.readString(this.path, StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalStateException("Attribute file is unreadable: " + this.path, exception);
        }
    }
}
