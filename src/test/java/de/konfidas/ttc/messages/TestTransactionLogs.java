package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import org.junit.Test;
import org.junit.jupiter.api.RepeatedTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.fail;

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

    @Test
    public void startTransactionLogMessageWithInvalidOperationType() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransactionT");
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
       try{
        TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
       catch(LogMessage.LogMessageParsingException e){
           //Exptected
           return;
       }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }



    @Test
    public void startTransactionLogMessageWithoutOperationType() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

       startTransactionLogBuilder.setOperationTypeToNull();
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
       try{
        TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
       catch(LogMessage.LogMessageParsingException e){
           //Expected
           return;
       }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @Test
    public void startTransactionLogMessageWithoutClientID() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientIDToNull();
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @Test
    public void startTransactionLogMessageWithoutProcessData() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setProcessDataToNull();
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @Test
    public void startTransactionLogMessageWithoutProcessType() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessTypeToNull();
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @Test
    public void startTransactionLogMessageWithAdditionalExternalData() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setAdditionalExternalData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            fail("Transaction Log Message parsing with Additional External Data failed");

        }


    }

    @Test
    public void startTransactionLogMessageWithAdditionalInternalData() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setAdditionalInternalData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            fail("Transaction Log Message parsing with Additional Internal Data failed");

        }


    }

    @Test
    public void startTransactionLogMessageWithAdditionalInternalDataAndAdditionalExternalData() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setAdditionalExternalData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setAdditionalInternalData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            fail("Transaction Log Message parsing with Additional Internal Data and AdditionalExternalData failed");

        }


    }

    @Test
    public void startTransactionLogMessageWithoutTransactionNumber() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setProcessData(new byte[] { 0x5f, 0x20,  0x3a, 0x69, 0x10 });
        startTransactionLogBuilder.setTransactionNumberToNull();


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @Test
    public void startTransactionLogMessageWithExtendedLenghtElements() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();
        int sizeProcessDataInByte = 500;
        byte[] randomProcessData = new byte[sizeProcessDataInByte];
        new Random().nextBytes(randomProcessData);
        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setProcessData(randomProcessData);
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
            //Expected
            fail("Transaction Log Message parsing failed with one element that has extended length");
            return;
        }

    }
    @RepeatedTest(10)
    public void startTransactionLogMessageWithRandomProcessData() throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException { ;
        StartTransactionLogMessageBuilder startTransactionLogBuilder = new StartTransactionLogMessageBuilder();

        int randomSizeProcessDataInByte = 1048576 + (int)(Math.random() * ((10485760 - 1048576) + 1));

        byte[] randomProcessData = new byte[randomSizeProcessDataInByte];
        new Random().nextBytes(randomProcessData);
        startTransactionLogBuilder.setOperationType("startTransaction");
        startTransactionLogBuilder.setClientID("client-ID kommt hier rein");
        startTransactionLogBuilder.setProcessType("Hier kann ein Wert für processType stehen");
        startTransactionLogBuilder.setProcessData(randomProcessData);
        startTransactionLogBuilder.setTransactionNumber(new BigInteger(new byte[] { 0x20}));


        byte[] startTransactionLog = startTransactionLogBuilder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = startTransactionLogBuilder.getFilename();
        try{
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);}
        catch(LogMessage.LogMessageParsingException e){
             fail("Transaction Log Message parsing failed with random process data (ha extended length)");
        }
return;
    }
}
