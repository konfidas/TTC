package de.konfidas.ttc.messages;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Primitive;

public class LogMessagePrinter {

    // TODO: create and use getter.
    static public String printMessage(LogMessage msg) {
        String return_value = String.format("The following log message has been extracted from file %s", msg.filename);
        return_value += System.lineSeparator();
        return_value += String.format("version: %d", msg.version);
        return_value += System.lineSeparator();
        return_value += String.format("certifiedDataType: %s", msg.certifiedDataType);
        return_value += System.lineSeparator();

        if (msg instanceof TransactionLogMessage){

            // If certifiedData is present, we have a transaction log
            return_value += String.format("[certifiedData]operationType: %s", ((TransactionLogMessage) msg).operationType);
            return_value += System.lineSeparator();
            return_value += String.format("[certifiedData]clientID: %s", ((TransactionLogMessage) msg).clientID);
            return_value += System.lineSeparator();
            return_value += String.format("[certifiedData]processData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).processData));
            return_value += System.lineSeparator();
            return_value += String.format("[certifiedData]processType: %s", ((TransactionLogMessage) msg).processType);
            return_value += System.lineSeparator();
            return_value += (((TransactionLogMessage)msg).additionalExternalData == null) ? "[certifiedData]No additionalExternalData" : String.format("[certifiedData]additionalExternaData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalExternalData));
            return_value += System.lineSeparator();
            return_value += String.format("[certifiedData]transactionNumber: %x", ((TransactionLogMessage) msg).transactionNumber);
            return_value += System.lineSeparator();
            return_value += (((TransactionLogMessage)msg).additionalInternalData == null) ? "[certifiedData]No additionalInternalData" : String.format("[certifiedData]additionalInternalData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalInternalData));
            return_value += System.lineSeparator();

        }

        for (ASN1Primitive certifiedDatum : msg.certifiedData) {
            return_value += String.format("certifiedData: %s", certifiedDatum.toString());
            return_value += System.lineSeparator();
        }

        return_value += String.format("serialNumber: %s", Hex.encodeHexString(msg.serialNumber));
        return_value += System.lineSeparator();
        return_value += String.format("signatureAlgorithm: %s", msg.signatureAlgorithm);
        return_value += System.lineSeparator();

        for (ASN1Primitive signatureAlgorithmParameter : msg.signatureAlgorithmParameters) {
            return_value += String.format("signatureAlgorithmParameter: %s", signatureAlgorithmParameter.toString());
            return_value += System.lineSeparator();
        }
        if (msg.seAuditData != null) {
            return_value += String.format("seAuditData: %s", msg.seAuditData.toString());
            return_value += System.lineSeparator();
        }

        return_value += String.format("signatureCounter: %d", msg.signatureCounter);
        return_value += System.lineSeparator();

        return_value += String.format("logTimeFormat:: %s", msg.logTimeType);
        return_value += System.lineSeparator();

        switch (msg.logTimeType) {
            case "unixTime":
                return_value += String.format("logTime: %d", msg.logTimeUnixTime);
                return_value += System.lineSeparator();
                break;
            case "utcTime":
                return_value += String.format("logTime: %s", msg.logTimeUTC);
                return_value += System.lineSeparator();
                break;
            case "generalizedTime":
                return_value += String.format("logTime: %s", msg.logTimeGeneralizedTime);
                return_value += System.lineSeparator();
                break;
        }

        return_value += String.format("signatureValue:: %s", Hex.encodeHexString(msg.signatureValue));
        return_value += System.lineSeparator();

        return_value += String.format("dtbs:: %s", Hex.encodeHexString(msg.dtbs));
        return_value += System.lineSeparator();

        return (return_value);
    }

}
