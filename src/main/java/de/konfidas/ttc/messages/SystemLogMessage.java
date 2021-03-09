package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.SystemLogParsingException;
import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLTaggedObject;

import java.io.IOException;
import java.util.Enumeration;

public class SystemLogMessage extends LogMessage {
    ASN1Primitive operationType;
    ASN1Primitive systemOperationData;
    ASN1Primitive additionalInternalData;


    public SystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    ASN1Primitive parseCertifiedData(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives) throws IOException, SystemLogParsingException {
        ASN1Primitive element = asn1Primitives.nextElement();

        element = parseOperationType(dtbsStream, asn1Primitives, element);
        element = parseSystemOperationData(dtbsStream, asn1Primitives, element);

        if (element instanceof ASN1OctetString){
            this.additionalInternalData = null;
            return element;
        }

        element = parseAdditionalInternalData(dtbsStream, asn1Primitives, element);

        return element;
    }

    ASN1Primitive parseAdditionalInternalData(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives, ASN1Primitive element) throws SystemLogParsingException, IOException {
        int tag;
        if(!(element instanceof  DLTaggedObject)){
            throw new SystemLogParsingException("additionalInternalData not found. Expected DLTaggedObject but got "+ element.getClass());
        }

        tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 2){
            throw new SystemLogParsingException("additionalInternalData not found. Expected Element [2] but got ["+tag+"]");
        }
        dtbsStream.write(element.getEncoded());
        additionalInternalData = element;
        element = asn1Primitives.nextElement();
        return element;
    }

    ASN1Primitive parseSystemOperationData(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives, ASN1Primitive element) throws SystemOperationDataParsingException, IOException {
        int tag;

        if(!(element instanceof  DLTaggedObject)){
            throw new SystemOperationDataParsingException("systemOperationData not found. Expected DLTaggedObject but got "+ element.getClass());
        }

        tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 1){
            throw new SystemOperationDataParsingException("systemOperationData not found. Expected Element [1] but got ["+tag+"]");
        }

        dtbsStream.write(element.getEncoded());
        systemOperationData = element;
        element = asn1Primitives.nextElement();
        return element;
    }

    ASN1Primitive parseOperationType(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives, ASN1Primitive element) throws OperationTypeParsingException, IOException {
        if(!(element instanceof DLTaggedObject)){
            throw new OperationTypeParsingException("operationType not found. Expected DLTaggedObject but got "+ element.getClass());
        }

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 0){
            throw new OperationTypeParsingException("operationType not found. Expected Element [0] but got ["+tag+"]");
        }

        dtbsStream.write(element.getEncoded());
        operationType = element;
        element = asn1Primitives.nextElement();
        return element;
    }


    public static class OperationTypeParsingException extends SystemLogParsingException{
        public OperationTypeParsingException(String message) {
            super(message);
        }
    }

    public static class SystemOperationDataParsingException extends SystemLogParsingException{
        public SystemOperationDataParsingException(String message) {
            super(message);
        }
    }

}
