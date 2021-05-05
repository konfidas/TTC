package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.util.List;
import java.util.ListIterator;

public class AuditLogMessage extends LogMessageImplementation {

    public AuditLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws IOException, LogMessageImplementation.LogMessageParsingException {
        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_SE_audit_log){
            throw new LogMessageImplementation.CertifiedDataTypeParsingException("Invalid Certified Data Type, expected id_SE_API_SE_audit_log but found "+this.certifiedDataType.getName(), null);
        }
    }

    @Override
        void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{

            if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("CertifiedData element not found"); }
            ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
            if (getEncodedTag(nextElement) >= 127 ) {
                throw new LogMessageParsingException("CertifiedData element found in an audit log message.");
            }

        }



    @Override
    void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("seAuditData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1OctetString)) {
            throw new LogMessageParsingException("seAuditData has to be ASN1OctetString, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();
        this.seAuditData = ((ASN1OctetString) element).getOctets();
        dtbsStream.write(this.getEncodedValue(element));
    }
}
