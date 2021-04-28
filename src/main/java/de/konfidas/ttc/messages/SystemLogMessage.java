package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLTaggedObject;

import java.io.IOException;
import java.util.List;
import java.util.ListIterator;

public abstract class SystemLogMessage extends LogMessage {
    ASN1Primitive operationType;
    DLTaggedObject systemOperationData;
    ASN1Primitive additionalInternalData;


    public SystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {

        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_system_log){
            throw new LogMessage.CertifiedDataTypeParsingException("Invalid Certified Data Type, expected id_SE_API_system_log but found "+this.certifiedDataType.getName(), null);
        }
    }


    @Override
    void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        parseOperationType(dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseSystemOperationDataElement(dtbsStream, logMessageAsASN1List, logMessageIterator);


        // systemOperationData has tag 0x81 (i.e. context-specific, not-constructed, but contains a constructed element
        // so BouncyCastle does not parse the content (because the tag does not signal, that there is ASN1 Structure within to parse.
        // for this reason, we have to manually parse the content, which we do here:
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        systemOperationData.encodeTo(baos);
        byte[] content = baos.toByteArray();
        content[0] = 0x30;

        try(ASN1InputStream inputStreamDecoder = new ASN1InputStream(content)) {
            parseSystemOperationDataContent(inputStreamDecoder);
        }
        // A clean solution would be, to fix the ASN1 definition of systemlogs and use a context-specific constructed tag here, i.e. 0xA1 instead of 0x81,
        // but this requires TR-03151 to be fixed.

        parseAdditionalInternalData(dtbsStream, logMessageAsASN1List, logMessageIterator);
    }


    void parseOperationType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new OperationTypeParsingException("operationsType element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            throw new OperationTypeParsingException("operationsType has to be DLTaggedObject, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 0){
            throw new OperationTypeParsingException("operationType not found. Expected Element [0] but got ["+tag+"]");
        }

        dtbsStream.write(element.getEncoded());
        operationType = element;

    }

    void parseSystemOperationDataElement(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new SystemOperationDataParsingException("SystemOperationData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            throw new SystemOperationDataParsingException("SystemOperationData has to be DLTaggedObject, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 1){
            throw new SystemOperationDataParsingException("systemOperationData not found. Expected Element [1] but got ["+tag+"]");
        }

        dtbsStream.write(element.getEncoded());
        systemOperationData = (DLTaggedObject)element;

    }

    protected abstract void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException;

    void parseAdditionalInternalData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("AdditionalInternalData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            additionalInternalData = null;
            return ;
        }

        ASN1Primitive element = logMessageIterator.next();

        if(!(element instanceof  DLTaggedObject)){
            throw new SystemLogParsingException("additionalInternalData not found. Expected DLTaggedObject but got "+ element.getClass());
        }

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 2){
            throw new SystemLogParsingException("additionalInternalData not found. Expected Element [2] but got ["+tag+"]");
        }
        dtbsStream.write(element.getEncoded());
        additionalInternalData = element;
    }

    @Override
        void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {

        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("seAuditData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if(nextElement instanceof  ASN1OctetString){
            throw new LogMessageParsingException("seAuditData element found in a system log message.");
        }

    }



    public class SystemLogParsingException extends LogMessageParsingException{
        public SystemLogParsingException(String message) { super(message); }
        public SystemLogParsingException(String message, Exception reason) {
            super(message, reason);
        }

    }
    public class OperationTypeParsingException extends SystemLogParsingException{
        public OperationTypeParsingException(String message) {
            super(message);
        }
    }

    public class SystemOperationDataParsingException extends SystemLogParsingException{
        public SystemOperationDataParsingException(String message) {
            super(message);
        }
    }

}
