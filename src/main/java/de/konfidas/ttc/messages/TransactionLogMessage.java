package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.List;
import java.util.ListIterator;



public class TransactionLogMessage extends LogMessageImplementation implements TransactionLog{
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    String operationType;
    String clientID;
    byte[] processData;
    String processType;
    byte[] additionalExternalData;
    BigInteger transactionNumber;
    byte[] additionalInternalData;

    @Override
    public String getOperationType() {
        return operationType;
    } // TODO: Enum instead of string?

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    @Override
    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public byte[] getProcessData() {
        return processData;
    }

    public void setProcessData(byte[] processData) {
        this.processData = processData;
    }

    public String getProcessType() {
        return processType;
    }

    public void setProcessType(String processType) {
        this.processType = processType;
    }

    public byte[] getAdditionalExternalData() {
        return additionalExternalData;
    }

    public void setAdditionalExternalData(byte[] additionalExternalData) {
        this.additionalExternalData = additionalExternalData;
    }

    @Override
    public BigInteger getTransactionNumber() {
        return transactionNumber;
    }

    public void setTransactionNumber(BigInteger transactionNumber) {
        this.transactionNumber = transactionNumber;
    }

    public byte[] getAdditionalInternalData() {
        return additionalInternalData;
    }

    public void setAdditionalInternalData(byte[] additionalInternalData) {
        this.additionalInternalData = additionalInternalData;
    }

    public TransactionLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }

    @Override
    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
//        void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives) throws IOException, LogMessage.CertifiedDataTypeParsingException, ExtendLengthValueExceedsInteger {
        super.parseCertifiedDataType(dtbsStream,logMessageAsASN1List,logMessageIterator);
        if(this.certifiedDataType != oid.id_SE_API_transaction_log){
            throw new LogMessageImplementation.CertifiedDataTypeParsingException("Invalid Certified Data Type, expected id_SE_API_transaction_log but found "+this.certifiedDataType.getName(), null);
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

        ASN1Primitive nextElement =  logMessageAsASN1List.get(logMessageIterator.nextIndex());

        if (!(nextElement instanceof DLTaggedObject)) { throw new LogMessageParsingException("operationType in certifiedData has to be DLApplicationSpecific, but is " + nextElement.getClass()); }

        if (((DLTaggedObject) nextElement).getTagNo()!=0){ throw new LogMessageParsingException("operationType in certifiedData has to have a tag of 0 (int), but is " + ((DLTaggedObject) nextElement).getTagNo()); }

        DLTaggedObject element = (DLTaggedObject)logMessageIterator.next();
        DERPrintableString innerElement = DERPrintableString.getInstance(element,false);
        operationType = innerElement.toString();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseClientID(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("clientID in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) { throw new LogMessageParsingException("clientID in certifiedData has to be DLTaggedObject, but is " + nextElement.getClass()); }

        if (((DLTaggedObject) nextElement).getTagNo() != 1){ throw new LogMessageParsingException("clientID in certifiedData has to have a tag of 1 (int), but is " + ((DLTaggedObject) nextElement).getTagNo()); }

        DLTaggedObject element = (DLTaggedObject)logMessageIterator.next();

        DERPrintableString innerElement = DERPrintableString.getInstance(element,false);
        clientID = innerElement.toString();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseProcessData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("processData in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if ((!(nextElement instanceof DLTaggedObject)&&!(nextElement instanceof BERTaggedObject ))) { throw new LogMessageParsingException("processData in certifiedData has to be DLTaggedObject or BERTaggedObject, but is " + nextElement.getClass()); }


        if (((ASN1TaggedObject) nextElement).getTagNo() != 2){ throw new LogMessageParsingException("processData in certifiedData has to have a tag of 2 (int), but is " + ((DLTaggedObject) nextElement).getTagNo()); }

        ASN1TaggedObject element = (ASN1TaggedObject)logMessageIterator.next();
        ASN1OctetString innerElement = ASN1OctetString.getInstance(element,false);

        processData = innerElement.getOctets();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseProcessType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("processType in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) { throw new LogMessageParsingException("processType in certifiedData has to be DLTaggedObject or BERTaggedObject, but is " + nextElement.getClass()); }

        if (((DLTaggedObject) nextElement).getTagNo() != 3){ throw new LogMessageParsingException("processType in certifiedData has to have a tag of 3 (int), but is " + ((DLTaggedObject) nextElement).getTagNo()); }

        DLTaggedObject element = (DLTaggedObject)logMessageIterator.next();
        DERPrintableString innerElement = DERPrintableString.getInstance(element, false);

        processType = innerElement.toString();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseAdditionalExternalData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{

        if (!logMessageIterator.hasNext()) {
            logger.debug("additionalExternalData in certifiedData not found for message: "+this.getFileName());
            return;
            }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
            logger.debug("additionalExternalData in certifiedData has to be DLTaggedObject, but is " + nextElement.getClass());
            return;

        }

        if (((DLTaggedObject) nextElement).getTagNo() != 4){
            logger.debug("additionalExternalData in certifiedData has to have a tag of 4 (int), but is " + ((DLTaggedObject) nextElement).getTagNo());
            return;
        }

        DLTaggedObject element = (DLTaggedObject)logMessageIterator.next();
        ASN1OctetString innerElement = ASN1OctetString.getInstance(element,false);

//        DEROctetString innerElement = (DEROctetString) element.getObject();

        additionalExternalData = innerElement.getOctets();
        dtbsStream.write(getEncodedValue(innerElement));


    }

    void parseTransactionNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("transactionNumber in certifiedData  not found"); }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) { throw new LogMessageParsingException("transactionNumber in certifiedData has to be DLTaggedObject, but is " + nextElement.getClass()); }

        if (((DLTaggedObject) nextElement).getTagNo() != 5){ throw new LogMessageParsingException("transactionNumber in certifiedData has to have a tag of 5 (int), but is " + ((DLTaggedObject) nextElement).getTagNo()); }

        DLTaggedObject element = (DLTaggedObject)logMessageIterator.next();
        ASN1Integer innerElement = ASN1Integer.getInstance(element,false);

        transactionNumber = innerElement.getValue();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    void parseAdditionalInternalData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException{
        if (!logMessageIterator.hasNext()) {
//            throw new LogMessageParsingException("additionalExternalData in certifiedData  not found");
//TODO: Logging
return;
        }

        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof DLTaggedObject)) {
//            throw new LogMessageParsingException("additionalExternalData in certifiedData has to be DLTaggedObject, but is " + nextElement.getClass());
//        TODO: logging
        return;
        }



        if (((DLTaggedObject) nextElement).getTagNo() != 6){
            //throw new LogMessageParsingException("additionalExternalData in certifiedData has to have a tag of 6 (int), but is " + ((DLTaggedObject) nextElement).getTagNo());
//        logging
            return;
        }

        DLTaggedObject element = (DLTaggedObject)logMessageIterator.next();
//        DEROctetString innerElement = (DEROctetString) element.getObject();
        ASN1OctetString innerElement = ASN1OctetString.getInstance(element,false);
//

        additionalInternalData = innerElement.getOctets();
        dtbsStream.write(getEncodedValue(innerElement));

    }

    @Override
    void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException {

        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("seAuditData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if(nextElement instanceof  ASN1OctetString){
            throw new LogMessageParsingException("seAuditData element found in a transaction log message.");
        }

    }


    @Override
    public int getVersion() {
        return this.version;
    }

    @Override
    public oid getCertifiedDataType() {
        return this.certifiedDataType;
    }

    @Override
    public Collection<ASN1Primitive> getSignatureAlgorithmParameters() {
        return this.signatureAlgorithmParameters;
    }

    @Override
    public byte[] getSeAuditData() {
        return this.seAuditData;
    }
}
