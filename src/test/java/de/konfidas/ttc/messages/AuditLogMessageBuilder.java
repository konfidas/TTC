package de.konfidas.ttc.messages;

import de.konfidas.ttc.setup.Utilities;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.util.Random;
import static de.konfidas.ttc.setup.Utilities.getEncodedValue;
public class AuditLogMessageBuilder extends LogMessageBuilder {


    @Override
    AuditLogMessageBuilder prepare() throws TestLogMessageCreationError {
            super.prepare();
        try {
        certifiedDataType = oid.id_SE_API_SE_audit_log;
        certifiedDataTypeAsASN1 = new ASN1ObjectIdentifier(certifiedDataType.getReadable());

        certifiedDataTypeEndcoded = getEncodedValue(certifiedDataTypeAsASN1);

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
    @Override
    String constructFileName() {
        switch (logTimeType) {
            case "unixTime":
                filename = "Unixt_" + logTimeUnixTime + "_Sig-";
                break;
            case "utcTime":
                filename = "UTCTime_" + logTimeUTC + "_Sig-";
                break;
            case "generalizedTime":
                filename = "Gent_" + logTimeGeneralizedTime + "_Sig-";
                break;
        }

        filename = filename + signatureCounter.toString();
        filename = filename + "_Log-Aud.log";
        return filename;
    }
}
