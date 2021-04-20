package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;


public class SignatureCounterValidator implements Validator{
    HashMap<String, BigInteger>  nextSignatureCounters;

    public SignatureCounterValidator(){
        nextSignatureCounters = new HashMap<>();
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        LinkedList<ValidationException> result = new LinkedList<>();

        ArrayList<LogMessage> messages = tar.getAll_log_messages();
        messages.sort(new LogMessage.SignatureCounterComparator());

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
                case -1: result.add(new SignatureCounterMissingException(serial,expectedSignatureCounter, foundSignatureCounter));
                         nextSignatureCounters.replace(serial, foundSignatureCounter.add(BigInteger.ONE));
                         break;
                case 0:  nextSignatureCounters.replace(serial, foundSignatureCounter.add(BigInteger.ONE));
                         break;
                case 1:  result.addAll(handleDuplicates(messages,msg));
            }
        }
        return result;
    }

    List<SignatureCounterDuplicateException> handleDuplicates(ArrayList<LogMessage> msgs, LogMessage msg) {
        BigInteger duplicateCounter = msg.getSignatureCounter();

        // FIXME: do not run over all message. only over previous ones:
        return msgs.stream()
                .filter(c -> c.getSignatureCounter().equals(duplicateCounter))
                .map(c -> new SignatureCounterDuplicateException(duplicateCounter, c, msg))
                .collect(Collectors.toList());
    }

    static class SignatureCounterMissingException extends ValidationException{
        String serial;
        BigInteger expected;
        BigInteger foundNext;

        public SignatureCounterMissingException(String serial, BigInteger expected, BigInteger foundNext) {
            this.expected = expected;
            this.foundNext = foundNext;
            this.serial = serial;
        }
    }

    static class SignatureCounterDuplicateException extends ValidationException{
        BigInteger expected;
        LogMessage msg;
        LogMessage msg1;

        public SignatureCounterDuplicateException(BigInteger expected, LogMessage msg1, LogMessage msg) {
            this.expected = expected;
            this.msg = msg;
            this.msg1 = msg1;
        }
    }
}
