package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLTaggedObject;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;

public class SystemLogMessage extends LogMessage {
    ASN1Primitive operationType;
    ASN1Primitive systemOperationData;
    ASN1Primitive additionalInternalData;


    public SystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {

//        void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives) throws IOException, LogMessage.CertifiedDataTypeParsingException, ExtendLengthValueExceedsInteger {
        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_system_log){
            throw new LogMessage.CertifiedDataTypeParsingException("Invalid Certified Data Type, expected id_SE_API_system_log but found "+this.certifiedDataType.getName(), null);
        }
    }


    @Override
        void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{

        parseOperationType(dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseSystemOperationData(dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseAdditionalInternalData(dtbsStream, logMessageAsASN1List, logMessageIterator);

    }


    void parseOperationType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("operationsType element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            throw new LogMessageParsingException("operationsType has to be DLTaggedObject, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 0){
            throw new OperationTypeParsingException("operationType not found. Expected Element [0] but got ["+tag+"]");
        }

        dtbsStream.write(element.getEncoded());
        operationType = element;

    }

    void parseSystemOperationData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("SystemOperationData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            throw new LogMessageParsingException("SystemOperationData has to be DLTaggedObject, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 1){
            throw new SystemOperationDataParsingException("systemOperationData not found. Expected Element [1] but got ["+tag+"]");
        }

        dtbsStream.write(element.getEncoded());
        systemOperationData = element;
    }

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
