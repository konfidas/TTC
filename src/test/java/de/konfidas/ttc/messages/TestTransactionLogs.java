package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

public class TestTransactionLogs extends TestCaseBasisWithCA {

    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    @Test
    public void valiStartTransactionLogMessage() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setSerialNumber(new byte[] { 0x4f, 0x20,  0x3a, 0x69, 0x10});
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        logger.info(LogMessagePrinter.printMessage(transactionLogMessage));

    }

}
