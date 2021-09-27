package de.konfidas.ttc.tars;

import de.konfidas.ttc.errors.TtcError;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.assertTrue;

public class AggregatedLogMessageArchiveMockTest {
    class TestTarMock implements LogMessageArchive {
        HashMap<String, X509Certificate> intermediates;
        HashMap<String, X509Certificate> client;
        ArrayList<LogMessage> messages;

        TestTarMock(){
            messages = new ArrayList<>();
        }

        @Override
        public Map<String, X509Certificate> getIntermediateCertificates() {
            return intermediates;
        }

        @Override
        public Map<String, X509Certificate> getClientCertificates() {
            return client;
        }

        @Override
        public ArrayList<TtcError> getAllErrors() {
            return new ArrayList<TtcError>();
        }

        @Override
        public Collection<LogMessage> getLogMessages() {
            return messages;
        }

        @Override
        public Collection<? extends LogMessage> getSortedLogMessages() {
            return null;
        }

        @Override
        public String getFileName() {
            return "";
        }
    }

    class LogMessageMock implements LogMessage{
        byte[] encoded;
        BigInteger signatureCounter;

        public LogMessageMock(byte[]encoded){
            this(encoded, BigInteger.ONE);
        }

        @Override
        public ArrayList<TtcError> getAllErrors() {
            return new ArrayList<TtcError>();
        }

        public LogMessageMock(byte[]encoded, BigInteger signatureCounter){
            this.encoded = encoded;
            this.signatureCounter = signatureCounter;
        }

        public boolean equals(Object o){
            if(o instanceof  LogMessage){
                return Arrays.equals(this.getEncoded(), ((LogMessage) o).getEncoded());
            }
            return false;
        }

        @Override
        public LogTime getLogTime() {
            return null;
        }

        @Override
        public BigInteger getSignatureCounter() {
            return signatureCounter;
        }

        @Override
        public byte[] getSerialNumber() {
            return new byte[0];
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
            return encoded;
        }

        @Override
        public int hashCode() {
            return java.util.Arrays.hashCode(encoded);
        }
    }


    @Test
    public void testTwoTars(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}));


        TestTarMock tar2 = new TestTarMock();
        tar2.messages.add(new LogMessageMock(new byte[]{0x01, 0x03}));


        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive();

        assertTrue(aTar.getLogMessages().size() == 0);

        aTar.addArchive(tar1);

        assertTrue(aTar.getLogMessages().size() == 1);

        aTar.addArchive(tar2);

        assertTrue(aTar.getLogMessages().size() == 2);

    }

    @Test
    public void testDuplicateContentFound(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}));


        TestTarMock tar2 = new TestTarMock();
        tar2.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}));


        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive();
        aTar.addArchive(tar1).addArchive(tar2);

        assertTrue(aTar.getLogMessages().size() == 1);
    }


    @Test
    public void testDuplicateContentInOneTarFound(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}));
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}));


        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive();
        aTar.addArchive(tar1);

        assertTrue(aTar.getLogMessages().size() == 1);
    }

    @Test
    public void testTwoTarsSorted(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}, BigInteger.ONE));

        TestTarMock tar2 = new TestTarMock();
        tar2.messages.add(new LogMessageMock(new byte[]{0x01, 0x03}, BigInteger.TWO));


        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive()
            .addArchive(tar1)
            .addArchive(tar2);

        assertTrue(aTar.getLogMessages().size() == 2);
        assertTrue(aTar.getSortedLogMessages().get(0).getSignatureCounter().equals(BigInteger.ONE));
        assertTrue(aTar.getSortedLogMessages().get(1).getSignatureCounter().equals(BigInteger.TWO));
    }

    @Test
    public void testTwoTarsSorted2(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}, BigInteger.TWO));

        TestTarMock tar2 = new TestTarMock();
        tar2.messages.add(new LogMessageMock(new byte[]{0x01, 0x03}, BigInteger.ONE));


        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive()
                .addArchive(tar1)
                .addArchive(tar2);

        assertTrue(aTar.getLogMessages().size() == 2);
        assertTrue(aTar.getSortedLogMessages().get(0).getSignatureCounter().equals(BigInteger.ONE));
        assertTrue(aTar.getSortedLogMessages().get(1).getSignatureCounter().equals(BigInteger.TWO));
    }

    @Test
    public void testTwoTarsSorted3(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}, BigInteger.TWO));
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x03}, BigInteger.ONE));



        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive()
                .addArchive(tar1);

        assertTrue(aTar.getLogMessages().size() == 2);
        assertTrue(aTar.getSortedLogMessages().get(0).getSignatureCounter().equals(BigInteger.ONE));
        assertTrue(aTar.getSortedLogMessages().get(1).getSignatureCounter().equals(BigInteger.TWO));
    }

    @Test
    public void testTwoTarsSorted4(){
        TestTarMock tar1 = new TestTarMock();
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x02}, BigInteger.ONE));
        tar1.messages.add(new LogMessageMock(new byte[]{0x01, 0x03}, BigInteger.TWO));

        AggregatedLogMessageArchive aTar = new AggregatedLogMessageArchive()
                .addArchive(tar1);

        assertTrue(aTar.getLogMessages().size() == 2);
        assertTrue(aTar.getSortedLogMessages().get(0).getSignatureCounter().equals(BigInteger.ONE));
        assertTrue(aTar.getSortedLogMessages().get(1).getSignatureCounter().equals(BigInteger.TWO));
    }


}

