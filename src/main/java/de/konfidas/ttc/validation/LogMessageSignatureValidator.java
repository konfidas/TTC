package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.LogMessageVerificationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessageSignatureVerifier;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

public class LogMessageSignatureValidator implements Validator {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    @Override
    public ValidationResult validate(LogMessageArchive tar) {
        LinkedList<ValidationException> errors = new LinkedList<>();

        LogMessageSignatureVerifier verifier = new LogMessageSignatureVerifier(tar.getClientCertificates());
        for (LogMessage msg : tar.getLogMessages()) {
            try {
                logger.debug("Checking signature of LogMessage {}", msg.getFileName());
                verifier.verify(msg);
            } catch (LogMessageVerificationException e) {
                errors.add(new LogMessageSignatureValidationException(msg,e));
            }
        }

        return new ValidationResultImpl().append(Collections.singleton(this), errors);
    }

    public static class LogMessageSignatureValidationException extends LogMessageValidationException{
        public LogMessageSignatureValidationException(LogMessage msg, Throwable t) {
            super(msg,t);
        }
    }
}
