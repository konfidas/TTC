package de.konfidas.ttc.messages;

import de.konfidas.ttc.setup.Utilities;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;

import static de.konfidas.ttc.setup.Utilities.getEncodedValue;


public abstract class TransactionLogMessageBuilder extends LogMessageBuilder{

    public String getOperationType() {
        return operationType;
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }
    public void setOperationTypeToNull() {
        this.operationType = null;
    }

    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }
    public void setClientIDToNull() {
        this.clientID = null;
    }

    public byte[] getProcessData() {
        return processData;
    }

    public void setProcessData(byte[] processData) {
        this.processData = processData;
    }
    public void setProcessDataToNull() {
    this.processData = null;
    }

    public String getProcessType() {
        return processType;
    }

    public void setProcessType(String processType) {
        this.processType = processType;
    }
    public void setProcessTypeToNull() {
        this.processType = null;
    }

    public byte[] getAdditionalExternalData() {
        return additionalExternalData;
    }

    public void setAdditionalExternalData(byte[] additionalExternalData) {
        this.additionalExternalData = additionalExternalData;
    }

    public BigInteger getTransactionNumber() {
        return transactionNumber;
    }

    public void setTransactionNumber(BigInteger transactionNumber) {
        this.transactionNumber = transactionNumber;
    }
    public void setTransactionNumberToNull() {
        this.transactionNumber = null;
    }

    public byte[] getAdditionalInternalData() {
        return additionalInternalData;
    }

    public void setAdditionalInternalData(byte[] additionalInternalData) {
        this.additionalInternalData = additionalInternalData;
    }

    public DLTaggedObject getOperationTypeAsASN1() {
        return operationTypeAsASN1;
    }

    public void setOperationTypeAsASN1(DLTaggedObject operationTypeAsASN1) {
        this.operationTypeAsASN1 = operationTypeAsASN1;
    }

    public void setOperationTypeAsASN1ToNull() {
        this.operationTypeAsASN1 = null;
    }

    public DLTaggedObject getClientIdAsASN1() {
        return clientIdAsASN1;
    }

    public void setClientIdAsASN1(DLTaggedObject clientIdAsASN1) {
        this.clientIdAsASN1 = clientIdAsASN1;
    }

    public DLTaggedObject getProcessDataAsASN1() {
        return processDataAsASN1;
    }

    public void setProcessDataAsASN1(DLTaggedObject processDataAsASN1) {
        this.processDataAsASN1 = processDataAsASN1;
    }

    public DLTaggedObject getProcessTypeAsASN1() {
        return processTypeAsASN1;
    }

    public void setProcessTypeAsASN1(DLTaggedObject processTypeAsASN1) {
        this.processTypeAsASN1 = processTypeAsASN1;
    }

    public DLTaggedObject getAdditionalExternalDataAsASN1() {
        return additionalExternalDataAsASN1;
    }

    public void setAdditionalExternalDataAsASN1(DLTaggedObject additionalExternalDataAsASN1) {
        this.additionalExternalDataAsASN1 = additionalExternalDataAsASN1;
    }

    public DLTaggedObject getTransactionNumberAsASN1() {
        return transactionNumberAsASN1;
    }

    public void setTransactionNumberAsASN1(DLTaggedObject transactionNumberAsASN1) {
        this.transactionNumberAsASN1 = transactionNumberAsASN1;
    }

    public DLTaggedObject getAdditionalInternalDataAsASN1() {
        return additionalInternalDataAsASN1;
    }

    public void setAdditionalInternalDataAsASN1(DLTaggedObject additionalInternalDataAsASN1) {
        this.additionalInternalDataAsASN1 = additionalInternalDataAsASN1;
    }

    String operationType;
    String clientID;
    byte[] processData;
    String processType;
    byte[] additionalExternalData;
    BigInteger transactionNumber;
    byte[] additionalInternalData;

    DLTaggedObject operationTypeAsASN1;
    DLTaggedObject clientIdAsASN1;
    DLTaggedObject processDataAsASN1;
    DLTaggedObject processTypeAsASN1;
    DLTaggedObject additionalExternalDataAsASN1;
    DLTaggedObject transactionNumberAsASN1;
    DLTaggedObject additionalInternalDataAsASN1;




    @Override
    TransactionLogMessageBuilder prepare() throws TestLogMessageCreationError {
        super.prepare();
        try {

            certifiedDataType = oid.id_SE_API_transaction_log;
            certifiedDataTypeAsASN1 = new ASN1ObjectIdentifier(certifiedDataType.getReadable());
            certifiedDataTypeEndcoded = getEncodedValue(certifiedDataTypeAsASN1);


            if (operationType != null) {operationTypeAsASN1 = new DLTaggedObject(false,0,new DERPrintableString(operationType));
                super.addCertifiedDataAsASN1(operationTypeAsASN1);}
            if (clientID!=null){
                clientIdAsASN1 = new DLTaggedObject(false,1,new DERPrintableString(clientID));
                super.addCertifiedDataAsASN1(clientIdAsASN1);}
            if (processData!=null){
                processDataAsASN1 = new DLTaggedObject(false,2,new DEROctetString(processData));
                super.addCertifiedDataAsASN1(processDataAsASN1);}
            if (processType != null){
                processTypeAsASN1 = new DLTaggedObject(false,3,new DERPrintableString(processType));
                super.addCertifiedDataAsASN1(processTypeAsASN1);}
            if (additionalExternalData != null){
                additionalExternalDataAsASN1 = new DLTaggedObject(false,4,new DEROctetString(additionalExternalData));
                super.addCertifiedDataAsASN1(additionalExternalDataAsASN1);}
            if (transactionNumber != null){
                transactionNumberAsASN1 = new DLTaggedObject(false,5,new ASN1Integer(transactionNumber));
                super.addCertifiedDataAsASN1(transactionNumberAsASN1);}
            if (additionalInternalData != null){
                additionalInternalDataAsASN1 = new DLTaggedObject(false,6,new DEROctetString(additionalInternalData));
                super.addCertifiedDataAsASN1(additionalInternalDataAsASN1);}


        }
        catch (IOException| Utilities.ExtendLengthValueExceedsInteger e) {
            throw new TestLogMessageCreationError("Fehler in der prepare Methode des TransactionLogMessageBuilders",e);
        }
        return this;

    }



}
