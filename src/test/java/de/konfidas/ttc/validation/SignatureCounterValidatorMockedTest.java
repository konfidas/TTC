package de.konfidas.ttc.validation;

import de.konfidas.ttc.errors.TtcError;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignatureCounterValidatorMockedTest {


    class TestTar implements LogMessageArchive {

        ArrayList<LogMessage> messages;

        public TestTar(ArrayList<LogMessage> messages) {
            super();
            this.messages = messages;
        }

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
        public ArrayList<TtcError> getAllErrors() {
            return new ArrayList<TtcError>();
        }

        @Override
        public Collection<? extends LogMessage> getSortedLogMessages() {
            return messages;
        }

        @Override
        public String getFileName() {
            return "";
        }
    }

    static class LogMessageMock implements LogMessage {
        BigInteger signatureCounter;
        byte[] serial;

        LogMessageMock(BigInteger signatureCounter) {
            this(signatureCounter, new byte[0]);
        }

        LogMessageMock(BigInteger signatureCounter, byte[] serial) {
            this.signatureCounter = signatureCounter;
            this.serial = serial;
        }


        @Override
        public LogTime getLogTime() {
            return null;
        }

        @Override
        public ArrayList<TtcError> getAllErrors() {
            return new ArrayList<TtcError>();
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
            return null;
        }

        @Override
        public String getSignatureAlgorithm() {
            return null;
        }

        @Override
        public byte[] getDTBS() {
            return new byte[0];
        }

        @Override
        public byte[] getSignatureValue() {
            return new byte[0];
        }

        @Override
        public int getVersion() {
            return 0;
        }

        @Override
        public oid getCertifiedDataType() {
            return null;
        }

        @Override
        public Collection<ASN1Primitive> getSignatureAlgorithmParameters() {
            return null;
        }

        @Override
        public byte[] getSeAuditData() {
            return new byte[0];
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    @Test
    public void testEmpty() {
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar(new ArrayList<LogMessage>());

        assertTrue(validator.validate(tar).getValidationErrors().isEmpty());
    }


    @Test
    public void testTwoMessagesOk() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE));
        messages.add(new LogMessageMock(BigInteger.TWO));
        LogMessageArchive tar = new TestTar(messages);

        assertTrue(validator.validate(tar).getValidationErrors().isEmpty());
    }

    @Test
    public void testTwoMessagesOk2() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE));
        messages.add(new LogMessageMock(BigInteger.TWO));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().isEmpty());
    }

    @Test
    public void testDuplicateCounter() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE));
        messages.add(new LogMessageMock(BigInteger.ONE));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 1);
    }

    @Test
    public void testMissingOne() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.TWO));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 1);
    }


    @Test
    public void testMissingCounter() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE));
        messages.add(new LogMessageMock(BigInteger.valueOf(3)));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 1);
    }


    // Testing multiple serial numbers in one tar:

    @Test
    public void testDuplicateCounterInDifferentSerials() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().isEmpty());
    }

    @Test
    public void testOk2() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        // This test makes sure, that SignatureCounterValidator sorts the messages w.r.t. to the content of the serial number,
        // and not with respect to the instance of the byte []
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().isEmpty());
    }


    @Test
    public void testOk3() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().isEmpty());
    }

    @Test
    public void testMissingCounterDifferentSerials() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.valueOf(3), new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 1);
    }

    @Test
    public void testMissingCounterDifferentSerialsTwice() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.valueOf(3), new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.valueOf(3), new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 2);
    }

    @Test
    public void testMissingOneDifferentSerialsTwice() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 2);
    }

    @Test
    public void testMissingOneDifferentSerials() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 1);
    }

    @Test
    public void testDuplicateCounterDifferentSerials() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);


        assertTrue(validator.validate(tar).getValidationErrors().size() == 1);
    }


    @Test
    public void testDuplicateCounterDifferentSerialsTwice() {
        SignatureCounterValidator validator = new SignatureCounterValidator();

        ArrayList<LogMessage> messages = new ArrayList<LogMessage>();
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.ONE, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x01}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        messages.add(new LogMessageMock(BigInteger.TWO, new byte[]{0x02}));
        LogMessageArchive tar = new TestTar(messages);

        assertTrue(validator.validate(tar).getValidationErrors().size() == 2);
    }

}
