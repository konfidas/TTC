package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLTaggedObject;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.ResourceBundle;

public abstract class SystemLogMessage extends LogMessageImplementation {
    ASN1Primitive operationType;
    DLTaggedObject systemOperationData;
    ASN1Primitive additionalInternalData;

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS


    public SystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {

        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_system_log){
            throw new LogMessageImplementation.CertifiedDataTypeParsingException(String.format(properties.getString("de.konfidas.ttc.messages.invalidCertifiedDataType2"),this.certifiedDataType.getName()), null);
        }
    }


    @Override
        void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{

//
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
        if (!logMessageIterator.hasNext()) { throw new OperationTypeParsingException(properties.getString("de.konfidas.ttc.messages.operationsTypeElementNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            throw new OperationTypeParsingException(String.format(properties.getString("de.konfidas.ttc.messages.operationsTypeInvalidType"), nextElement.getClass()));
        }

        ASN1Primitive element = logMessageIterator.next();

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 0){
            throw new OperationTypeParsingException(String.format(properties.getString("de.konfidas.ttc.messages.operationTypeNotFound"),tag));
        }

        dtbsStream.write(element.getEncoded());
        operationType = element;

    }

    void parseSystemOperationDataElement(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new SystemOperationDataParsingException(properties.getString("de.konfidas.ttc.message.systemOperationDataNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            throw new SystemOperationDataParsingException(String.format(properties.getString("de.konfidas.ttc.message.systemOperationDataWrongType"), nextElement.getClass()));
        }

        ASN1Primitive element = logMessageIterator.next();

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 1){
            throw new SystemOperationDataParsingException(String.format(properties.getString("de.konfidas.ttc.message.systemOperationDataWrongExpectedElement"),tag));
        }

        dtbsStream.write(element.getEncoded());
        systemOperationData = (DLTaggedObject) element;
    }

    protected abstract void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException;

    void parseAdditionalInternalData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.additonalInternalDataNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            additionalInternalData = null;
            return ;
        }

        ASN1Primitive element = logMessageIterator.next();

        if(!(element instanceof  DLTaggedObject)){
            throw new SystemLogParsingException(String.format(MessageFormat.format(properties.getString("de.konfidas.ttc.message.additionalInternalDataWrongType"), element.getClass())));
        }

        int tag = ((DLTaggedObject) element).getTagNo() ;
        if (tag != 2){
            throw new SystemLogParsingException(String.format(properties.getString("de.konfidas.ttc.message.additionalInternalDataWrongElement"),tag));
        }
        dtbsStream.write(element.getEncoded());
        additionalInternalData = element;
    }

    @Override
    void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException {

        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.message.seAuditDataNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if(nextElement instanceof  ASN1OctetString){
            throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.message.seAuditDataNotFound "));
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
