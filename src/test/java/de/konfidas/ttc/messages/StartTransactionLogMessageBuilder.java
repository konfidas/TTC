package de.konfidas.ttc.messages;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;

public class StartTransactionLogMessageBuilder extends TransactionLogMessageBuilder{

 public StartTransactionLogMessageBuilder(){
     operationType = "startTransaction";
     clientID = "pleaseSetClientID";
     processData =new byte[] { 0x4f, 0x20,  0x3a, 0x69, 0x10};
     transactionNumber = new BigInteger(new byte[] { 0x00});
 }
    @Override
    StartTransactionLogMessageBuilder prepare() throws TestLogMessageCreationError {

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

        super.prepare();

        return this;

    }

    @Override
    String constructFileName() {
        switch (logTimeType) {
            case "unixTime":
                filename = "Unixt_" + logTimeUnixTime + "_Sig-";
                break;
            case "utcTime":
                filename = "UTCTime_" + logTimeUTC + "_Sig-";
                break;
            case "generalizedTime":
                filename = "Gent_" + logTimeGeneralizedTime + "_Sig-";
                break;
        }

        filename = filename + signatureCounter.toString();
        filename += (transactionNumber == null) ? "_Log_No-_Start" : "_Log_No-" +transactionNumber.toString()+ "_Start";
        filename += (clientID == null) ? ".log" : clientID.toString()+".log";
        return filename;
    }


}
