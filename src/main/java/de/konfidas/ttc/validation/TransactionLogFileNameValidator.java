package de.konfidas.ttc.validation;


import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLog;
import de.konfidas.ttc.messages.TransactionLogMessage;

import java.math.BigInteger;
import java.util.Collection;
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
    protected LinkedList<ValidationException> checkMsg(LogMessage msg) {
        if(msg instanceof TransactionLog) {
            LinkedList<ValidationException> result = super.checkMsg(msg);

            String[] components = getComponents();

            if(components.length >= 5) {
                result.addAll(checkTransCounter(components[4], (TransactionLog) msg));
            }else{
                result.add(new MissingComponentException(msg));
            }

            if(components.length >= 6) {
                result.addAll(checkType(components[5], (TransactionLog)  msg));
            }else{
                result.add(new MissingComponentException(msg));
            }

            if(components.length >= 7) {
                result.addAll(checkClient(components[6], (TransactionLog) msg));
            }

            return result;
        }else{
            return new LinkedList<>();
        }
    }

    Collection<ValidationException> checkType(String component, TransactionLog msg) {
        LinkedList<ValidationException> result = new LinkedList<>();

        if(     (!component.equals("Start")) &&
                (!component.equals("Update")) &&
                (!component.equals("Finish"))){
            result.add(new UnknownOperationTypeException(component, msg));
        }

        if(!(component+"Transaction").equals(msg.getOperationType())){
            result.add(new OperationTypeMismatchException(component, msg.getOperationType(), msg));
        }

        return result;
    }

    Collection<ValidationException> checkClient(String component, TransactionLog msg) {
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

    Collection<ValidationException> checkTransCounter(String component, TransactionLog msg) {
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
        UnknownOperationTypeException(String found, LogMessage msg) {
            super(msg, null);
            this.found = found;
        }
    }
    public static class BadFormattedTransTagException extends LogMessageFileNameValidationException{
        BadFormattedTransTagException(LogMessage msg) { super(msg, null); }
    }

    public static class MissingTransTagException extends LogMessageFileNameValidationException{
        MissingTransTagException(LogMessage msg) { super(msg, null); }
    }

    public static class DifferentTransCounterException extends LogMessageFileNameValidationException{
        BigInteger expected;
        BigInteger found;
        DifferentTransCounterException(BigInteger expected, BigInteger found, LogMessage msg) {
            super(msg, null);
            this.expected = expected;
            this.found = found;
        }
    }

    public static class BadFormattedClientTagException extends LogMessageFileNameValidationException{
        BadFormattedClientTagException(LogMessage msg) { super(msg, null); }
    }


    public static class MissingClientTagException extends LogMessageFileNameValidationException{
        MissingClientTagException(LogMessage msg) { super(msg, null); }
    }

    public static class OperationTypeMismatchException extends LogMessageFileNameValidationException{
        String expected;
        String found;

        OperationTypeMismatchException(String expected, String found, LogMessage msg) {
            super(msg, null);
            this.expected = expected;
            this.found = found;
        }
    }

    public static class DifferentClientException extends LogMessageFileNameValidationException{
        String expected;
        String found;
        DifferentClientException(String expected, String found, LogMessage msg) {
            super(msg, null);
            this.expected = expected;
            this.found = found;
        }
    }
}
