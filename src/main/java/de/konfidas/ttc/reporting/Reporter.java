package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;

import java.util.Collection;

public interface Reporter<T> {
    Report<T> createReport(Collection<LogMessageArchive> logs, ValidationResult vResult);
}
