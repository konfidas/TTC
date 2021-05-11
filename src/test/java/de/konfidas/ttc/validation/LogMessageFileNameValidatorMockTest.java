package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
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
    static class LMM extends LogMessageMock {
        BigInteger signatureCounter;
        byte[] serial;
        LogTime time;
        String filename;

       LMM(BigInteger signatureCounter, byte[] serial, LogTime time, String filename){
            this.signatureCounter = signatureCounter;
            this.serial = serial;
            this.filename = filename;
            this.time = time;
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
}
