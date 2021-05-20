package de.konfidas.ttc.validation;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1Primitive;

import java.math.BigInteger;
import java.util.Collection;

public class LogMessageMock implements LogMessage {
    @Override
    public LogTime getLogTime() {
        return null;
    }

    @Override
    public BigInteger getSignatureCounter() {
        return null;
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
        return new byte[0];
    }
}
