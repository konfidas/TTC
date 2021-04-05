package de.konfidas.ttc.messages;

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

    public DLApplicationSpecific getOperationTypeAsASN1() {
        return operationTypeAsASN1;
    }

    public void setOperationTypeAsASN1(DLApplicationSpecific operationTypeAsASN1) {
        this.operationTypeAsASN1 = operationTypeAsASN1;
    }

    public DLApplicationSpecific getClientIdAsASN1() {
        return clientIdAsASN1;
    }

    public void setClientIdAsASN1(DLApplicationSpecific clientIdAsASN1) {
        this.clientIdAsASN1 = clientIdAsASN1;
    }

    public DLApplicationSpecific getProcessDataAsASN1() {
        return processDataAsASN1;
    }

    public void setProcessDataAsASN1(DLApplicationSpecific processDataAsASN1) {
        this.processDataAsASN1 = processDataAsASN1;
    }

    public DLApplicationSpecific getProcessTypwAsASN1() {
        return processTypwAsASN1;
    }

    public void setProcessTypwAsASN1(DLApplicationSpecific processTypwAsASN1) {
        this.processTypwAsASN1 = processTypwAsASN1;
    }

    public DLApplicationSpecific getAdditionalExternalDataAsASN1() {
        return additionalExternalDataAsASN1;
    }

    public void setAdditionalExternalDataAsASN1(DLApplicationSpecific additionalExternalDataAsASN1) {
        this.additionalExternalDataAsASN1 = additionalExternalDataAsASN1;
    }

    public DLApplicationSpecific getTransactionNumberAsASN1() {
        return transactionNumberAsASN1;
    }

    public void setTransactionNumberAsASN1(DLApplicationSpecific transactionNumberAsASN1) {
        this.transactionNumberAsASN1 = transactionNumberAsASN1;
    }

    public DLApplicationSpecific getAdditionalInternalDataAsASN1() {
        return additionalInternalDataAsASN1;
    }

    public void setAdditionalInternalDataAsASN1(DLApplicationSpecific additionalInternalDataAsASN1) {
        this.additionalInternalDataAsASN1 = additionalInternalDataAsASN1;
    }

    String operationType;
    String clientID;
    byte[] processData;
    String processType;
    byte[] additionalExternalData;
    BigInteger transactionNumber;
    byte[] additionalInternalData;

    DLApplicationSpecific operationTypeAsASN1;
    DLApplicationSpecific clientIdAsASN1;
    DLApplicationSpecific processDataAsASN1;
    DLApplicationSpecific processTypwAsASN1;
    DLApplicationSpecific additionalExternalDataAsASN1;
    DLApplicationSpecific transactionNumberAsASN1;
    DLApplicationSpecific additionalInternalDataAsASN1;


    @Override
    TransactionLogMessageBuilder prepare() throws TestLogMessageCreationError {
        super.prepare();

        certifiedDataType = oid.id_SE_API_transaction_log;

        certifiedDataTypeAsASN1 = new ASN1ObjectIdentifier(certifiedDataType.getReadable());



        return this;

    }


}
