package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;

// FIXME: this is incomplete and does not work fully.
public class TransactionCounterValidator implements Validator {
    final HashMap<BigInteger,OpenTransaction> openTransactions;
    BigInteger transactionCounter;

    TransactionCounterValidator(){
        openTransactions = new HashMap<>();
        transactionCounter = BigInteger.ONE;
    }

    public Collection<ValidationException> validate(LogMessageArchive tar){
        ArrayList<ValidationException> result = new ArrayList<>();

        Collection<LogMessage> msgs = tar.getSortedLogMessages();

        for(LogMessage msg : msgs){
            if(msg instanceof TransactionLogMessage){
                result.addAll(updateState((TransactionLogMessage) msg));
            }
        }

        return result;
    }



    Collection<ValidationException> updateState(TransactionLogMessage msg) {
        LinkedList <ValidationException> result = new LinkedList<>();

        if("START".equals(msg.getProcessType())){
            if(!transactionCounter.equals(msg.getTransactionNumber())){
                result.add(new WrongTransactionCounterException(transactionCounter, msg));
            }

            if(openTransactions.containsKey(msg.getTransactionNumber())){
                OpenTransaction duplicate = openTransactions.get(msg.getTransactionNumber());
                result.add(new DuplicateTransactionCounterFoundException(duplicate.msgs.get(0), msg));
                duplicate.msgs.add(msg);
                duplicate.signatureCounterLastUpdate = msg.getSignatureCounter();
            }else{
                openTransactions.put(msg.getTransactionNumber(), new OpenTransaction(msg));
            }

            // TODO: what is the next expected transaction number?
            // transactionCounter +1 or msg.getTransactionNumber +1?
            transactionCounter = transactionCounter.add(BigInteger.ONE);
        }

        if("UPDATE".equals(msg.getProcessType())){
            if(!openTransactions.containsKey(msg.getTransactionNumber())){
                result.add(new UpdateForNotOpenTransactionException(transactionCounter, msg));
            }else{
                // TODO
            }
        }

        if("FINISH".equals(msg.getProcessType())){
            // TODO
        }

        return result;
    }


    static class OpenTransaction{
        BigInteger signatureCounterLastUpdate;
        final LinkedList<TransactionLogMessage> msgs;

        public OpenTransaction(TransactionLogMessage msg) {
            this.signatureCounterLastUpdate = msg.getSignatureCounter();
            msgs = new LinkedList<>();
            msgs.add(msg);
        }
    }


    static class DuplicateTransactionCounterFoundException extends LogMessageValidationException {
        final TransactionLogMessage msg2;

        public DuplicateTransactionCounterFoundException(TransactionLogMessage msg1, TransactionLogMessage msg2) {
            super(msg1);
            this.msg2 = msg2;
        }
    }

    static class UpdateForNotOpenTransactionException extends LogMessageValidationException{
        final BigInteger expectedTransactionCounter;

        public UpdateForNotOpenTransactionException(BigInteger transactionCounter, TransactionLogMessage msg) {
            super(msg);
            this.expectedTransactionCounter = transactionCounter;
        }
    }

    static class WrongTransactionCounterException extends LogMessageValidationException{
        final BigInteger expectedTransactionCounter;

        public WrongTransactionCounterException(BigInteger transactionCounter, TransactionLogMessage msg) {
            super(msg);
            this.expectedTransactionCounter = transactionCounter;
        }
    }
}
