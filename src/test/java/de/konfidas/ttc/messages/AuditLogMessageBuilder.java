package de.konfidas.ttc.messages;

import de.konfidas.ttc.setup.Utilities;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.text.ParseException;
import java.util.Random;
import static de.konfidas.ttc.setup.Utilities.getEncodedValue;
public class AuditLogMessageBuilder extends LogMessageBuilder {


    @Override
    AuditLogMessageBuilder prepare() throws TestLogMessageCreationError {
            super.prepare();
        certifiedDataType = oid.id_SE_API_SE_audit_log;
        certifiedDataTypeAsASN1 = new ASN1ObjectIdentifier(certifiedDataType.getReadable());
        try {
            certifiedDataEncoded = getEncodedValue(certifiedDataTypeAsASN1);

        //FIXME: Sinnhafte Auditdaten wären schön
        byte[] b = new byte[20];
        new Random().nextBytes(b);

        seAuditData = b;
        seAuditDataAsASN1 = new DEROctetString(seAuditData);
        seAuditDataEncoded = getEncodedValue(seAuditDataAsASN1);
        }
        catch (IOException| Utilities.ExtendLengthValueExceedsInteger e) {
            throw new TestLogMessageCreationError("Fehler in der prepare Methode des AuditLogMessageBuilders",e);
        }
        return this;

    }
}
