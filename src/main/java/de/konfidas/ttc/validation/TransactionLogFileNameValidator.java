package de.konfidas.ttc.validation;


import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

/**
 * BSI-TR03151 specifies the filenames of log messages in exported TARs. This Validator validates, the filenames
 * according to the specification.
 *
 * Section 5.1.2.1 on Page 56 specifies for transaction logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_No-TRANSACTION_TYPE_Client-CLIENT-ID_Fc-FILE-COUNTER.log
 */
public class TransactionLogFileNameValidator extends AbstractLogMessageFileNameValidator{
    final static String LogFormat="Log-Tra";

    @Override
    protected String getExpectedLogFormat(){
        return LogFormat;
    }

    @Override
    protected Collection<? extends ValidationException> checkLogFormat(String component, LogMessage msg) {
        if(!LogFormat.equals(component)){
            return Collections.singleton(new WrongLogFormatException(LogFormat, component, msg));
        }
        return null;
    }

    @Override
    protected LinkedList<ValidationException> checkMsg(LogMessage msg) {
        if(msg instanceof TransactionLogMessage) {
            LinkedList<ValidationException> result = super.checkMsg(msg);

            String[] components = msg.getFileName().split("_");

            if(components.length >= 5) {
                result.addAll(checkTransCounter(components[4], (TransactionLogMessage) msg));
            }else{
                result.add(new MissingComponentException(msg));
            }

            if(components.length >= 6) {
                result.addAll(checkType(components[5], msg));
            }else{
                result.add(new MissingComponentException(msg));
            }

            if(components.length >= 7) {
                result.addAll(checkClient(components[6], (TransactionLogMessage) msg));
            }

            return result;
        }else{
            return new LinkedList<>();
        }
    }

    Collection<ValidationException> checkType(String component, LogMessage msg) {
        LinkedList<ValidationException> result = new LinkedList<>();

        if(     (!component.equals("Start")) &&
                (!component.equals("Update")) &&
                (!component.equals("Finish"))){
            result.add(new UnknownOperationTypeException(component, msg));
        }
        return result;
    }

    Collection<ValidationException> checkClient(String component, TransactionLogMessage msg) {
        LinkedList<ValidationException> result = new LinkedList<>();

        String[] client = component.split("-");

        if(!(client.length == 2)){
            result.add(new BadFormattedClientTagException(msg));
            return result;
        }

        if(!client[0].equals("Client")){
            result.add(new MissingClientTagException(msg));
        }


        if(!(msg.getClientID().equals(client[1]))){
            result.add(new DifferentClientException(client[1], msg.getClientID(), msg));
        }

        return result;
    }

    Collection<ValidationException> checkTransCounter(String component, TransactionLogMessage msg) {
        LinkedList<ValidationException> result = new LinkedList<>();

        String[] transCounter = component.split("-");

        if(!(transCounter.length == 2)){
            result.add(new BadFormattedTransTagException(msg));
            return result;
        }

        if(!transCounter[0].equals("No")){
            result.add(new MissingTransTagException(msg));
        }

        BigInteger found = new BigInteger(transCounter[1]);
        if(!(msg.getTransactionNumber().equals(found))){
            result.add(new DifferentTransCounterException(found, msg.getTransactionNumber(), msg));
        }

        return result;
    }

    public static class UnknownOperationTypeException extends LogMessageFileNameValidationException{
        String found;
        public UnknownOperationTypeException(String found, LogMessage msg) {
            super(msg, null);
            this.found = found;
        }
    }
    public static class BadFormattedTransTagException extends LogMessageFileNameValidationException{
        public BadFormattedTransTagException(LogMessage msg) { super(msg, null); }
    }

    public static class MissingTransTagException extends LogMessageFileNameValidationException{
        public MissingTransTagException(LogMessage msg) { super(msg, null); }
    }

    public static class DifferentTransCounterException extends LogMessageFileNameValidationException{
        BigInteger expected;
        BigInteger found;
        public DifferentTransCounterException(BigInteger expected, BigInteger found, LogMessage msg) {
            super(msg, null);
            this.expected = expected;
            this.found = found;
        }
    }

    public static class BadFormattedClientTagException extends LogMessageFileNameValidationException{
        public BadFormattedClientTagException(LogMessage msg) { super(msg, null); }
    }


    public static class MissingClientTagException extends LogMessageFileNameValidationException{
        public MissingClientTagException(LogMessage msg) { super(msg, null); }
    }


    public static class DifferentClientException extends LogMessageFileNameValidationException{
        String expected;
        String found;
        public DifferentClientException(String expected, String found, LogMessage msg) {
            super(msg, null);
            this.expected = expected;
            this.found = found;
        }
    }
}
