package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;



public class TransactionLogMessage extends LogMessage {
    String operationType ="";
    String clientID ="";
    byte[] processData;
    String processType="";
    byte[] additionalExternalData;
    int transactionNumber;
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
//    void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
//    void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
//    void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
//    void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{

    }
