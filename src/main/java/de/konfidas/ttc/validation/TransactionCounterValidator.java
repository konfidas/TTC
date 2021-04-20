package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.tars.LogMessageArchive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

public class TransactionCounterValidator implements Validator {
    HashMap<Integer,OpenTransaction> openTransactions;
    int transactionCounter;

    TransactionCounterValidator(){
        openTransactions = new HashMap<>();
        transactionCounter = 0;
    }

    public Collection<Exception> validate(LogMessageArchive tar){
        ArrayList<Exception> result = new ArrayList<>();

        ArrayList<LogMessage> msgs = tar.getAll_log_messages();
        msgs.sort(new LogMessage.SignatureCounterComparator());


        for(LogMessage msg : msgs){
            if(msg instanceof TransactionLogMessage){
                updateState((TransactionLogMessage) msg);
            }
        }


        return result;
    }



    void updateState(TransactionLogMessage msg) {

        msg.
    }


    static class OpenTransaction{
        int transactionNumber;
        int signatureCounterLastUpdate;
        LogTime lastUpdateTime;
    }
}
