package de.konfidas.ttc.messages;

import java.math.BigInteger;

public interface TransactionLog extends LogMessage{

    BigInteger getTransactionNumber();
    String getClientID();
    String getOperationType();
}
