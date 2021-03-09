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

        for (ASN1Primitive certifiedDatum : msg.certifiedData) {
            return_value += String.format("certifiedData: %s", certifiedDatum.toString());
            return_value += System.lineSeparator();
        }

        return_value += String.format("serialNumber: %s", Hex.encodeHexString(msg.serialNumber));
        return_value += System.lineSeparator();
        return_value += String.format("signatureAlgorithm: %s", msg.signatureAlgorithm);
        return_value += System.lineSeparator();

        for (ASN1Primitive signatureAlgorithmParameter : msg.signatureAlgorithmParameters) {
            return_value += String.format("certifiedData: %s", signatureAlgorithmParameter.toString());
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
