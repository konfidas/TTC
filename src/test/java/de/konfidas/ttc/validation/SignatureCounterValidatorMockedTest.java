package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class SignatureCounterValidatorMockedTest {
    ArrayList<LogMessage> messages;

    public SignatureCounterValidatorMockedTest(){
        messages = new ArrayList<>();
    }

    class TestTar implements LogMessageArchive{
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
    }
    static class LMM extends LogMessageMock {
        BigInteger signatureCounter;
        byte[] serial;
        LMM(BigInteger signatureCounter){
            this(signatureCounter,new byte[0]);
        }

        LMM(BigInteger signatureCounter, byte[] serial){
            this.signatureCounter = signatureCounter;
            this.serial = serial;
        }

        @Override
        public BigInteger getSignatureCounter() {
            return signatureCounter;
        }

        @Override
        public byte[] getSerialNumber() {
            return serial;
        }
    }

    @Before
    public void clean(){
        messages.clear();
    }


    @Test
    public void testEmpty(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        assertTrue(validator.validate(tar).isEmpty());
    }

    @Test
    public void testTwoMessagesOk(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE));
        this.messages.add(new LMM(BigInteger.TWO));

        assertTrue(validator.validate(tar).isEmpty());
    }

    @Test
    public void testTwoMessagesOk2(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.TWO));
        this.messages.add(new LMM(BigInteger.ONE));

        assertTrue(validator.validate(tar).isEmpty());
    }

    @Test
    public void testDuplicateCounter(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE));
        this.messages.add(new LMM(BigInteger.ONE));

        assertTrue(validator.validate(tar).size()==1);
    }

    @Test
    public void testMissingOne(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.TWO));

        assertTrue(validator.validate(tar).size()==1);
    }



    @Test
    public void testMissingCounter(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE));
        this.messages.add(new LMM(BigInteger.valueOf(3)));

        assertTrue(validator.validate(tar).size()==1);
    }


    // Testing multiple serial numbers in one tar:

    @Test
    public void testDuplicateCounterInDifferentSerials(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));

        assertTrue(validator.validate(tar).isEmpty());
    }

    @Test
    public void testOk2(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        // This test makes sure, that SignatureCounterValidator sorts the messages w.r.t. to the content of the serial number,
        // and not with respect to the instance of the byte []
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));

        assertTrue(validator.validate(tar).isEmpty());
    }


    @Test
    public void testOk3(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));

        assertTrue(validator.validate(tar).isEmpty());
    }

    @Test
    public void testMissingCounterDifferentSerials(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.valueOf(3), new byte[]{0x02}));

        assertTrue(validator.validate(tar).size() == 1);
    }

    @Test
    public void testMissingCounterDifferentSerialsTwice(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.valueOf(3), new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.valueOf(3), new byte[]{0x02}));

        assertTrue(validator.validate(tar).size() == 2);
    }

    @Test
    public void testMissingOneDifferentSerialsTwice(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));

        assertTrue(validator.validate(tar).size() == 2);
    }

    @Test
    public void testMissingOneDifferentSerials(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));

        assertTrue(validator.validate(tar).size() == 1);
    }

    @Test
    public void testDuplicateCounterDifferentSerials(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));

        assertTrue(validator.validate(tar).size() == 1);
    }


    @Test
    public void testDuplicateCounterDifferentSerialsTwice(){
        SignatureCounterValidator validator = new SignatureCounterValidator();
        LogMessageArchive tar = new TestTar();

        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));
        this.messages.add(new LMM(BigInteger.TWO, new byte[]{0x02}));
        this.messages.add(new LMM(BigInteger.ONE, new byte[]{0x01}));

        assertTrue(validator.validate(tar).size() == 2);
    }

}
