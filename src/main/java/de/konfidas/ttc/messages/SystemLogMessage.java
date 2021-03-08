package de.konfidas.ttc.messages;

import de.konfidas.ttc.MyByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;

public class SystemLogMessage extends LogMessage {
    public SystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    ASN1Primitive parseCertifiedData(MyByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> test) throws IOException {
        ASN1Primitive element;
        // Now, we will enter a while loop and collect all the certified data
        element = test.nextElement();
        while (!(element instanceof ASN1OctetString)) {
            // Then, the object identifier for the certified data type shall follow
            this.certifiedData.add(element);
            byte[] elementValue = Arrays.copyOfRange(element.getEncoded(), 2, element.getEncoded().length);
            dtbsStream.write(elementValue);

            element = test.nextElement();
        }
        return element;
    }
}
