package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;



public class TransactionLogMessage extends LogMessage {
    String operationType ="";
    String clientID ="";
    byte[] processData;
    String processType="";
    byte[] additionalExternalData;
    BigInteger transactionNumber;
    byte[] additionalInternalData;

    public TransactionLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
//        void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives) throws IOException, LogMessage.CertifiedDataTypeParsingException, ExtendLengthValueExceedsInteger {
        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_transaction_log){
            throw new LogMessage.CertifiedDataTypeParsingException("Invalid Certified Data Type, expected id_SE_API_transaction_log but found "+this.certifiedDataType.getName(), null);
        }
    }

    @Override
    void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        parseOperationType( dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseClientID( dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseProcessData( dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseProcessType( dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseAdditionalExternalData( dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseTransactionNumber( dtbsStream, logMessageAsASN1List, logMessageIterator);
        parseAdditionalInternalData( dtbsStream, logMessageAsASN1List, logMessageIterator);


    }

    void parseOperationType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("operationType in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) { throw new LogMessageParsingException("operationType in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass()); }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 128){ throw new LogMessageParsingException("operationType in certifiedData has to have a tag of 128 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag()); }

        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1Primitive innerElement = element.getObject();

        operationType = innerElement.toString();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseClientID(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("clientID in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) { throw new LogMessageParsingException("clientID in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass()); }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 129){ throw new LogMessageParsingException("clientID in certifiedData has to have a tag of 129 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag()); }

        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1Primitive innerElement = element.getObject();

        clientID = innerElement.toString();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseProcessData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("processData in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) { throw new LogMessageParsingException("processData in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass()); }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 130){ throw new LogMessageParsingException("processData in certifiedData has to have a tag of 130 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag()); }

        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1OctetString innerElement = (ASN1OctetString) element.getObject();

        processData = innerElement.getOctets();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseProcessType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("processType in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) { throw new LogMessageParsingException("processType in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass()); }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 131){ throw new LogMessageParsingException("processType in certifiedData has to have a tag of 131 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag()); }

        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1Primitive innerElement = element.getObject();

        processType = innerElement.toString();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseAdditionalExternalData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("additionalExternalData in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) {
//            throw new LogMessageParsingException("additionalExternalData in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass());
        return;
        }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 132){
          return;
        //    throw new LogMessageParsingException("additionalExternalData in certifiedData has to have a tag of 131 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag());
        }

        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1OctetString innerElement = (ASN1OctetString) element.getObject();

        additionalExternalData = innerElement.getOctets();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseTransactionNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("transactionNumber in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) { throw new LogMessageParsingException("transactionNumber in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass()); }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 133){ throw new LogMessageParsingException("transactionNumber in certifiedData has to have a tag of 133 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag()); }

        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1Integer innerElement = (ASN1Integer)element.getObject();

        transactionNumber = innerElement.getValue();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseAdditionalInternalData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("additionalInternalData in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLApplicationSpecific)) {
//            throw new LogMessageParsingException("additionalInternalData in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass());
            return;
        }

        if (((DLApplicationSpecific) nextElement).getApplicationTag() != 134){
            return;
//                throw new LogMessageParsingException("additionalInternalData in certifiedData has to have a tag of 131 (int), but is " + ((DLApplicationSpecific) nextElement).getApplicationTag());
        }
        DLApplicationSpecific element = (DLApplicationSpecific)logMessageIterator.next();
        ASN1OctetString innerElement = (ASN1OctetString) element.getObject();

        additionalExternalData = innerElement.getOctets();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    @Override
    void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {

        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("seAuditData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if(nextElement instanceof  ASN1OctetString){
            throw new LogMessageParsingException("seAuditData element found in a transaction log message.");
        }

    }

    }
