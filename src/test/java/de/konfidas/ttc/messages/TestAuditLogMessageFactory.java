package de.konfidas.ttc.messages;

import de.konfidas.ttc.messages.TestLogMessageFactory;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

import java.text.ParseException;
import java.util.Random;

public class TestAuditLogMessageFactory extends TestLogMessageFactory {


    @Override
    void prepare() {
        try {
            super.prepare();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        certifiedDataType = oid.id_SE_API_SE_audit_log;
        certifiedDataTypeAsASN1 = new ASN1ObjectIdentifier(certifiedDataType.getReadable());

        //FIXME: Sinnhafte Auditdaten wären schön
        byte[] b = new byte[20];
        new Random().nextBytes(b);

        seAuditData = b;
        seAuditDataAsASN1 = new DEROctetString(seAuditData);

    }
}
