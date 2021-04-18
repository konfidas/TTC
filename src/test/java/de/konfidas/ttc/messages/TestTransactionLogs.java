package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.setup.TestCaseBasisWithCA;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.fail;

public class TestTransactionLogs extends TestCaseBasisWithCA {

    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

public static String[][] provideParameters() {
    return new String[][] { { "de.konfidas.ttc.messages.StartTransactionLogMessageBuilder", "StartTransaction"}, { "de.konfidas.ttc.messages.UpdateTransactionLogMessageBuilder", "UpdateTransaction"},{ "de.konfidas.ttc.messages.FinishTransactionLogMessageBuilder", "FinishTransaction"}};
}

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void testValidTransactionLogMessage(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        ;
        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setSerialNumber(new byte[]{0x4f, 0x20, 0x3a, 0x69, 0x10});
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));

        byte[] transactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        TransactionLogMessage transactionLogMessage = new TransactionLogMessage(transactionLog, filename);
        logger.info(LogMessagePrinter.printMessage(transactionLogMessage));

    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithInvalidOperationType(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        ;
        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString+"b");
        builder.setSerialNumber(new byte[]{0x4f, 0x20, 0x3a, 0x69, 0x10});
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            //Exptected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithoutOperationType(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        ;
        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationTypeToNull();
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithoutClientID(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, ClassNotFoundException {
        ;
        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType("startTransaction");
        builder.setClientIDToNull();
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithoutProcessData(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, ClassNotFoundException {
        ;
        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessDataToNull();
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }
    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithoutProcessType(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessTypeToNull();
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }
    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithAdditionalExternalData(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        ;
        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setAdditionalExternalData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            fail("Transaction Log Message parsing with Additional External Data failed");

        }


    }
    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithAdditionalInternalData(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setAdditionalInternalData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            fail("Transaction Log Message parsing with Additional Internal Data failed");

        }


    }
    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithAdditionalInternalDataAndAdditionalExternalData(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setAdditionalExternalData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setAdditionalInternalData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            fail("Transaction Log Message parsing with Additional Internal Data and AdditionalExternalData failed");

        }


    }
    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithoutTransactionNumber(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(new byte[]{0x5f, 0x20, 0x3a, 0x69, 0x10});
        builder.setTransactionNumberToNull();


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
        } catch (LogMessage.LogMessageParsingException e) {
            //Expected
            return;
        }
        fail("Transaction Log Message parsing successful, but expected to fail");

    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithExtendedLenghtElements(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        int sizeProcessDataInByte = 500;
        byte[] randomProcessData = new byte[sizeProcessDataInByte];
        new Random().nextBytes(randomProcessData);
        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(randomProcessData);
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
            byte[] processDataFromBuiltTransactionLog = transactionLogMessage.getProcessData();
            assert (processDataFromBuiltTransactionLog.length == sizeProcessDataInByte);

        } catch (LogMessage.LogMessageParsingException e) {
            fail("Transaction Log Message parsing failed with one element that has extended length");
            return;
        }

    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void startTransactionLogMessageWithRandomProcessData(String builderClassString, String operationTypeString) throws LogMessageBuilder.TestLogMessageCreationError, BadFormatForLogMessageException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> builderClass = Class.forName(builderClassString);
        TransactionLogMessageBuilder builder = (TransactionLogMessageBuilder) builderClass.getDeclaredConstructor().newInstance();

        int randomSizeProcessDataInByte = 1048576 + (int) (Math.random() * ((10485760 - 1048576) + 1));

        byte[] randomProcessData = new byte[randomSizeProcessDataInByte];
        new Random().nextBytes(randomProcessData);
        builder.setOperationType(operationTypeString);
        builder.setClientID("client-ID kommt hier rein");
        builder.setProcessType("Hier kann ein Wert für processType stehen");
        builder.setProcessData(randomProcessData);
        builder.setTransactionNumber(new BigInteger(new byte[]{0x20}));


        byte[] startTransactionLog = builder.prepare()
                .calculateDTBS()
                .sign(getClientCertKeyPair().getPrivate())
                .build()
                .finalizeMessage();

        String filename = builder.getFilename();
        try {
            TransactionLogMessage transactionLogMessage = new TransactionLogMessage(startTransactionLog, filename);
            byte[] processDataFromBuiltTransactionLog = transactionLogMessage.getProcessData();
            assert (processDataFromBuiltTransactionLog.length == randomSizeProcessDataInByte);
        } catch (LogMessage.LogMessageParsingException e) {
            fail("Transaction Log Message parsing failed with random process data (ha extended length)");
        }
        return;
    }


}
