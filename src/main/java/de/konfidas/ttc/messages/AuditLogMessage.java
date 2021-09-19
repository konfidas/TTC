package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.ResourceBundle;

public class AuditLogMessage extends LogMessageImplementation {
    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);  //NON-NLS

    public AuditLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws IOException {
        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_SE_audit_log){
            this.allErrors.add(new LogMessageImplementation.CertifiedDataTypeParsingError(String.format(properties.getString("de.konfidas.ttc.messages.invalidCertifiedDataType"),this.certifiedDataType.getName()), null));
//            throw new LogMessageImplementation.CertifiedDataTypeParsingException(String.format(properties.getString("de.konfidas.ttc.messages.invalidCertifiedDataType"),this.certifiedDataType.getName()), null);
        }
    }

    @Override
        void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{

            if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.certifiedDataElementNotFound")); }
            ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
            if (getEncodedTag(nextElement) >= 127 ) {
                this.allErrors.add(new LogMessageParsingError(properties.getString("de.konfidas.ttc.messages.certifiedDataElementNotFound")));
//                throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.certifiedDataElementNotFound"));
            }
        }


    @Override
    void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.seAuditDataNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1OctetString)) {
//            throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.seAuditDataWrongDatatype"),  nextElement.getClass()));
            this.allErrors.add(new LogMessageParsingError(String.format(properties.getString("de.konfidas.ttc.messages.seAuditDataWrongDatatype"),  nextElement.getClass())));
            return;
        }

        ASN1Primitive element = logMessageIterator.next();
        this.seAuditData = ((ASN1OctetString) element).getOctets();
        dtbsStream.write(this.getEncodedValue(element));
    }
}
