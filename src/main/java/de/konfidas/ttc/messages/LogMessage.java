package de.konfidas.ttc.messages;

import de.konfidas.ttc.errors.TtcError;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1Primitive;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public interface LogMessage {
    LogTime getLogTime();
    BigInteger getSignatureCounter();
    byte[] getSerialNumber();
    String getFileName();
    String getSignatureAlgorithm();
    byte[] getDTBS();
    byte[] getSignatureValue();
    int getVersion();
    oid getCertifiedDataType();
    Collection<ASN1Primitive> getSignatureAlgorithmParameters();
    ArrayList<TtcError> getAllErrors();

    byte[] getSeAuditData();



    byte[] getEncoded();
}
