package de.konfidas.ttc.messages;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Primitive;

public class LogMessagePrinter {

    static public String printMessage(LogMessage msg) {
        StringBuilder return_value = new StringBuilder(String.format("The following log message has been extracted from file %s", msg.getFileName()));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("version: %d", msg.getVersion()));
        return_value.append( System.lineSeparator());
        return_value.append(String.format("certifiedDataType: %s", msg.getCertifiedDataType()));
        return_value.append( System.lineSeparator());

        if (msg instanceof TransactionLogMessage){return_value.append(printCertifiedDataOfTransactionLogMessage(msg)); }

        //TODO: Sind die folgenden Zeilen üpberflüssig?

//        for (ASN1Primitive certifiedDatum : msg.certifiedData) {
//            return_value.append(String.format("certifiedData: %s", certifiedDatum.toString()));
//            return_value.append(System.lineSeparator());
//        }

        return_value.append(String.format("serialNumber: %s", Hex.encodeHexString(msg.getSerialNumber())));
        return_value.append(System.lineSeparator());

        printSignatureAlgorithm(msg);

        printSeAuditData(msg);

        return_value.append(String.format("signatureCounter: %d", msg.getSignatureCounter()));
        return_value.append(System.lineSeparator());

        return_value.append(String.format("logTimeFormat:: %s", msg.getLogTime().getType()));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("logTime: %s", msg.getLogTime().toString()));

        printSignatureData(msg);


        return (return_value.toString());
    }

    static public String printCertifiedDataOfTransactionLogMessage(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        return_value.append(String.format("[certifiedData]operationType: %s", ((TransactionLogMessage) msg).operationType));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]clientID: %s", ((TransactionLogMessage) msg).clientID));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]processData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).processData)));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]processType: %s", ((TransactionLogMessage) msg).processType));
        return_value.append(System.lineSeparator());
        return_value.append((((TransactionLogMessage)msg).additionalExternalData == null) ? "[certifiedData]No additionalExternalData" : String.format("[certifiedData]additionalExternaData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalExternalData)));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]transactionNumber: %x", ((TransactionLogMessage) msg).transactionNumber));
        return_value.append(System.lineSeparator());
        return_value.append((((TransactionLogMessage)msg).additionalInternalData == null) ? "[certifiedData]No additionalInternalData" : String.format("[certifiedData]additionalInternalData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalInternalData)));
        return_value.append(System.lineSeparator());
        return_value.append(System.lineSeparator());

        return(return_value.toString());

    }

    static public String printSignatureAlgorithm(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        return_value.append(String.format("signatureAlgorithm: %s", msg.getSignatureAlgorithm()));
        return_value.append(System.lineSeparator());

        for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
            return_value.append(String.format("signatureAlgorithmParameter: %s", signatureAlgorithmParameter.toString()));
            return_value.append(System.lineSeparator());
        }

        return(return_value.toString());

    }

    static public String printSeAuditData(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        if (msg.getSeAuditData() != null) {
            return_value.append(String.format("seAuditData: %s", Hex.encodeHexString(msg.getSeAuditData())));
            return_value.append(System.lineSeparator());
        }


        return(return_value.toString());

    }

    static public String printSignatureData(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        return_value.append(String.format("signatureValue:: %s", Hex.encodeHexString(msg.getSignatureValue())));
        return_value.append(System.lineSeparator());

        return_value.append(String.format("dtbs:: %s", Hex.encodeHexString(msg.getDTBS())));
        return_value.append(System.lineSeparator());

        return(return_value.toString());

    }
}
