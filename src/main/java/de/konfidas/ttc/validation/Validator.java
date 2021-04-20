package de.konfidas.ttc.validation;

import de.konfidas.ttc.tars.LogMessageArchive;

import java.util.Collection;

public interface Validator {
    public Collection<Exception> validate(LogMessageArchive tar);
}
