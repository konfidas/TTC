package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLog;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class LogMessageFileNameValidatorMockTest {

    ArrayList<LogMessage> messages;

    public LogMessageFileNameValidatorMockTest(){
        messages = new ArrayList<>();
    }

    class TestTar implements LogMessageArchive {
        @Override
        public Map<String, X509Certificate> getIntermediateCertificates() {
            return null;
        }

        @Override
        public Map<String, X509Certificate> getClientCertificates() {
            return null;
        }

        @Override
        public Collection<LogMessage> getLogMessages() {
            return messages;
        }

        @Override
        public Collection<? extends LogMessage> getSortedLogMessages() {
            return messages;
        }
    }
    static class LMM extends LogMessageMock implements TransactionLog {
        BigInteger signatureCounter;
        BigInteger transactionCounter;
        byte[] serial;
        LogTime time;
        String filename;
        String client;
        String operationType;

       LMM(BigInteger signatureCounter, BigInteger transactionCounter, String operationType,  String client, byte[] serial, LogTime time, String filename){
            this.signatureCounter = signatureCounter;
            this.serial = serial;
            this.filename = filename;
            this.time = time;
            this.transactionCounter = transactionCounter;
            this.client = client;
            this.operationType = operationType;
        }

        @Override
        public LogTime getLogTime() {
            return time;
        }

        @Override
        public BigInteger getSignatureCounter() {
            return signatureCounter;
        }

        @Override
        public byte[] getSerialNumber() {
            return serial;
        }

        @Override
        public String getFileName() {
            return filename;
        }

        @Override
        public BigInteger getTransactionNumber() {
            return transactionCounter;
        }

        @Override
        public String getClientID() {
            return client;
        }

        @Override
        public String getOperationType() {
            return operationType;
        }
    }

    @Before
    public void clean(){
        messages.clear();
    }


    @Test
    public void testEmpty(){
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();
        LogMessageArchive tar = new TestTar();
        assertTrue(validator.validate(tar).isEmpty());
    }


    @Test
    public void testEmptyFileName() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(null, null, "", "",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                ""));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 8);
    }

    @Test
    public void testExampleFromTr() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Start_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.isEmpty());
    }

    @Test
    public void testExampleFromTr_Update() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Update",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Update_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.isEmpty());
    }

    @Test
    public void testExampleFromTr_Finish() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Finish",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Finish_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.isEmpty());
    }

    @Test
    public void testExampleFromTr_OperationMismatch() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Update",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Finish_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.OperationTypeMismatchException);
    }

    @Test
    public void testExampleFromTr_OperationBroken() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Foo",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Foo_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.UnknownOperationTypeException);
    }

    @Test
    public void testExampleFromTr_OperationBrokenMismatch() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Foo",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Bar_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 2);
    }

    @Test
    public void testExampleFromTr_ClientMismatch() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "04",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Start_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.DifferentClientException);
    }

    @Test
    public void testExampleFromTr_ClientBroken() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "04",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Start_Client03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.BadFormattedClientTagException);
    }

    @Test
    public void testExampleFromTr_ClientTagBroken() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-713_Start_Cli3nt-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.MissingClientTagException);
    }

    @Test
    public void testExampleFromTr_TransCounterMismatch() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No-712_Start_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.DifferentTransCounterException);
    }

    @Test
    public void testExampleFromTr_TransCounterTagBroken() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_No712_Start_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.BadFormattedTransTagException);
    }

    @Test
    public void testExampleFromTr_TransCounterTagWrong() throws ParseException {
        LogMessageFileNameValidator validator = new LogMessageFileNameValidator();

        messages.add(new LMM(BigInteger.valueOf(1572),
                BigInteger.valueOf(713),
                "Start",
                "03",
                new byte[]{},
                new UtcLogTime(new ASN1UTCTime("181109153045Z")),
                "Utc_181109153045Z_Sig-1572_Log-Tra_Nr-713_Start_Client-03.log"));

        LogMessageArchive tar = new TestTar();
        Collection<ValidationException> r = validator.validate(tar);
        assertTrue(r.size() == 1);
        assertTrue(r.stream().findFirst().get() instanceof TransactionLogFileNameValidator.MissingTransTagException);
    }

}
