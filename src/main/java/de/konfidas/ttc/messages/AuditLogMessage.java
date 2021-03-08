package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

public class AuditLogMessage extends LogMessage {

    public AuditLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    ASN1Primitive parseCertifiedData(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives) throws IOException, BadFormatForLogMessageException {
        ASN1Primitive element;
        // Now, we will enter a while loop and collect all the certified data
        element = asn1Primitives.nextElement();
        while (!(element instanceof ASN1OctetString)) {
            // Then, the object identifier for the certified data type shall follow
            this.certifiedData.add(element);
            byte[] elementValue = Arrays.copyOfRange(element.getEncoded(), 2, element.getEncoded().length);
            dtbsStream.write(elementValue);

            element = asn1Primitives.nextElement();
        }
        return element;
    }

}
