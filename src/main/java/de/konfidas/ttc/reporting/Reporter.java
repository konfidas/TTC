package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.TtcException;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;

import java.util.Collection;

public interface Reporter<T> {
    T createReport(Collection<LogMessageArchive> logs, ValidationResult vResult, Boolean skipLegitMessages) throws ReporterException;
//    T createReport(Collection<LogMessageArchive> logs, ValidationResult vResult) throws ReporterException;


    public class ReporterException extends TtcException {
        public ReporterException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
