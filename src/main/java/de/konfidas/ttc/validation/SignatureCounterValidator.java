package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessageImplementation;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.*;


public class SignatureCounterValidator implements Validator{
    final HashMap<String, BigInteger> nextSignatureCounters;

    // we operate on sorted log messages, so if we are in the case, that multiple log messages have the
    // same signature counters, we process them one after another. To create meaningful exceptions, we track
    // the previously processed Log Message:
    LogMessage previousMessage = null;
    // Note: This fails, if multiple tar-archives are presented to one validator in the wrong order, i.e.
    // not starting with the smallest signature counters!


    public SignatureCounterValidator(){
        nextSignatureCounters = new HashMap<>();
    }

    @Override
    public ValidationResult validate(LogMessageArchive tar) {
        LinkedList<ValidationException> result = new LinkedList<>();

        Collection<? extends LogMessage> messages =tar.getSortedLogMessages();

        BigInteger expectedSignatureCounter;
        String serial;

        for(LogMessage msg : messages){
            serial = Hex.encodeHexString(msg.getSerialNumber());

            BigInteger foundSignatureCounter = msg.getSignatureCounter();
            if(!nextSignatureCounters.containsKey(serial)){
                nextSignatureCounters.put(serial, BigInteger.ONE);
                expectedSignatureCounter = BigInteger.ONE;
            }else{
                expectedSignatureCounter = nextSignatureCounters.get(serial);
            }

            switch(expectedSignatureCounter.compareTo(foundSignatureCounter)){
                case -1: result.add(new SignatureCounterMissingException(msg, serial, expectedSignatureCounter, foundSignatureCounter));
                         nextSignatureCounters.replace(serial, foundSignatureCounter.add(BigInteger.ONE));
                         break;
                case 0:  nextSignatureCounters.replace(serial, foundSignatureCounter.add(BigInteger.ONE));
                         break;
                case 1:  result.add( new SignatureCounterDuplicateException(foundSignatureCounter,msg,previousMessage));
            }

            previousMessage = msg;
        }
        return new ValidationResultImpl().append(Collections.singleton(this), result);
    }

    static class SignatureCounterMissingException extends LogMessageValidationException {
        final String serial;
        final BigInteger expected;
        final BigInteger foundNext;

        public SignatureCounterMissingException(LogMessage msg, String serial, BigInteger expected, BigInteger foundNext) {
            super(msg);
            this.expected = expected;
            this.foundNext = foundNext;
            this.serial = serial;
        }
    }

    static class SignatureCounterDuplicateException extends LogMessageValidationException{
        final BigInteger expected;
        final LogMessage msg1;

        public SignatureCounterDuplicateException(BigInteger expected, LogMessage msg, LogMessage msg1) {
            super(msg);
            this.expected = expected;
            this.msg1 = msg1;
        }
    }
}
