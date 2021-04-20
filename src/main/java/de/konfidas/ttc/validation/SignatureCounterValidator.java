package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureCounterValidator implements Validator{
    BigInteger nextSignatureCounter;

    public SignatureCounterValidator(){
        nextSignatureCounter = BigInteger.ONE;
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        LinkedList<ValidationException> result = new LinkedList<>();

        ArrayList<LogMessage> msgs = tar.getAll_log_messages();
        msgs.sort(new LogMessage.SignatureCounterComparator());

        for(LogMessage msg : msgs){
            BigInteger foundSignatureCounter = msg.getSignatureCounter();

            switch(nextSignatureCounter.compareTo(foundSignatureCounter)){
                case -1: result.add(new SignatureCounterMissingException(nextSignatureCounter, foundSignatureCounter));
                         nextSignatureCounter = foundSignatureCounter.add(BigInteger.ONE);
                         break;
                case 0:  nextSignatureCounter = foundSignatureCounter.add(BigInteger.ONE);
                         break;
                case 1:  result.addAll(handleDuplicates(msgs,msg));
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
        BigInteger expected;
        BigInteger foundNext;

        public SignatureCounterMissingException(BigInteger expected, BigInteger foundNext) {
            this.expected = expected;
            this.foundNext = foundNext;
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
