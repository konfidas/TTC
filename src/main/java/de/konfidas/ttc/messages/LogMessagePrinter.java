package de.konfidas.ttc.messages;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Primitive;

import java.util.Locale;
import java.util.ResourceBundle;

public class LogMessagePrinter {
    static Locale locale = new Locale("de", "DE");//NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

    static public String printMessage(LogMessage msg){

        StringBuilder return_value = new StringBuilder(String.format(properties.getString("de.konfidas.ttc.messages.printLogMessageStart"), msg.getFileName()));
        return_value.append(System.lineSeparator());
        return_value.append(String.format("version: %d", msg.getVersion()));//NON-NLS
        return_value.append( System.lineSeparator());
        return_value.append(String.format("certifiedDataType: %s", msg.getCertifiedDataType()));//NON-NLS
        return_value.append( System.lineSeparator());

        if (msg instanceof TransactionLogMessage){return_value.append(printCertifiedDataOfTransactionLogMessage(msg)); }

        return_value.append(String.format("serialNumber: %s", Hex.encodeHexString(msg.getSerialNumber())));//NON-NLS
        return_value.append(System.lineSeparator());

        printSignatureAlgorithm(msg);

        printSeAuditData(msg);

        return_value.append(String.format("signatureCounter: %d", msg.getSignatureCounter()));//NON-NLS
        return_value.append(System.lineSeparator());

        return_value.append(String.format("logTimeFormat:: %s", msg.getLogTime().getType()));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append(String.format("logTime: %s", msg.getLogTime().toString()));//NON-NLS

        printSignatureData(msg);


        return (return_value.toString());
    }

    static public String printCertifiedDataOfTransactionLogMessage(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        return_value.append(String.format("[certifiedData]operationType: %s", ((TransactionLogMessage) msg).operationType));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]clientID: %s", ((TransactionLogMessage) msg).clientID));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]processData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).processData)));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]processType: %s", ((TransactionLogMessage) msg).processType));
        return_value.append(System.lineSeparator());
        return_value.append((((TransactionLogMessage)msg).additionalExternalData == null) ? "[certifiedData]No additionalExternalData" : String.format("[certifiedData]additionalExternaData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalExternalData)));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append(String.format("[certifiedData]transactionNumber: %x", ((TransactionLogMessage) msg).transactionNumber));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append((((TransactionLogMessage)msg).additionalInternalData == null) ? "[certifiedData]No additionalInternalData" : String.format("[certifiedData]additionalInternalData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalInternalData)));//NON-NLS
        return_value.append(System.lineSeparator());
        return_value.append(System.lineSeparator());

        return(return_value.toString());

    }

    static public String printSignatureAlgorithm(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        return_value.append(String.format("signatureAlgorithm: %s", msg.getSignatureAlgorithm()));//NON-NLS
        return_value.append(System.lineSeparator());

        for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
            return_value.append(String.format("signatureAlgorithmParameter: %s", signatureAlgorithmParameter.toString()));//NON-NLS
            return_value.append(System.lineSeparator());
        }

        return(return_value.toString());

    }

    static public String printSeAuditData(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        if (msg.getSeAuditData() != null) {
            return_value.append(String.format("seAuditData: %s", Hex.encodeHexString(msg.getSeAuditData())));//NON-NLS
            return_value.append(System.lineSeparator());
        }


        return(return_value.toString());

    }

    static public String printSignatureData(LogMessage msg) {
        StringBuilder return_value = new StringBuilder();

        return_value.append(String.format("signatureValue:: %s", Hex.encodeHexString(msg.getSignatureValue())));//NON-NLS
        return_value.append(System.lineSeparator());

        return_value.append(String.format("dtbs:: %s", Hex.encodeHexString(msg.getDTBS())));//NON-NLS
        return_value.append(System.lineSeparator());

        return(return_value.toString());

    }
}
