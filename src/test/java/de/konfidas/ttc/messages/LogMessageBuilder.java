package de.konfidas.ttc.messages;

import de.konfidas.ttc.setup.Utilities;
import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import static de.konfidas.ttc.setup.Utilities.getEncodedValue;


public abstract class LogMessageBuilder {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    public int getVersion() {
        return version;
    }

    public LogMessageBuilder setVersion(int version) {
        this.version = version;
        return this;
    }



    public oid getCertifiedDataType() {
        return certifiedDataType;
    }

    public LogMessageBuilder setCertifiedDataType(oid certifiedDataType) {
        this.certifiedDataType = certifiedDataType;
        return this;
    }

    public ArrayList<ASN1Primitive> getCertifiedData() {
        return certifiedData;
    }

    public LogMessageBuilder setCertifiedData(ArrayList<ASN1Primitive> certifiedData) {
        this.certifiedData = certifiedData;
        return this;
    }

    public byte[] getSerialNumber() {
        return serialNumber;
    }

    public LogMessageBuilder setSerialNumber(byte[] serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public LogMessageBuilder setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public ArrayList<ASN1Primitive> getSignatureAlgorithmParameters() {
        return signatureAlgorithmParameters;
    }

    public LogMessageBuilder setSignatureAlgorithmParameters(ArrayList<ASN1Primitive> signatureAlgorithmParameters) {
        this.signatureAlgorithmParameters = signatureAlgorithmParameters;
        return this;
    }

    public String getLogTimeType() {
        return logTimeType;
    }

    public LogMessageBuilder setLogTimeType(String logTimeType) {
        this.logTimeType = logTimeType;
        return this;
    }

    public String getLogTimeUTC() {
        return logTimeUTC;
    }

    public LogMessageBuilder setLogTimeUTC(String logTimeUTC) {
        this.logTimeUTC = logTimeUTC;
        return this;
    }

    public String getLogTimeGeneralizedTime() {
        return logTimeGeneralizedTime;
    }

    public void setLogTimeGeneralizedTime(String logTimeGeneralizedTime) {
        this.logTimeGeneralizedTime = logTimeGeneralizedTime;
    }

    public long getLogTimeUnixTime() {
        return logTimeUnixTime;
    }

    public LogMessageBuilder setLogTimeUnixTime(long logTimeUnixTime) {
        this.logTimeUnixTime = logTimeUnixTime;
        return this;
    }

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public LogMessageBuilder setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    public BigInteger getSignatureCounter() {
        return signatureCounter;
    }

    public LogMessageBuilder setSignatureCounter(BigInteger signatureCounter) {
        this.signatureCounter = signatureCounter;
        return this;
    }

    public byte[] getSeAuditData() {
        return seAuditData;
    }

    public LogMessageBuilder setSeAuditData(byte[] seAuditData) {
        this.seAuditData = seAuditData;
        return this;
    }

    public byte[] getDtbs() {
        return dtbs;
    }

    public LogMessageBuilder setDtbs(byte[] dtbs) {
        this.dtbs = dtbs;
        return this;
    }

    public LogMessageBuilder setFilename(String filename) {
        this.filename = filename;
        return this;
    }

    public ASN1EncodableVector getLogMessageVector() {
        return logMessageVector;
    }

    public LogMessageBuilder setLogMessageVector(ASN1EncodableVector logMessageVector) {
        this.logMessageVector = logMessageVector;
        return this;
    }

    public ASN1Integer getVersionAsASN1() {
        return versionAsASN1;
    }

    public LogMessageBuilder setVersionAsASN1(ASN1Integer versionAsASN1) {
        this.versionAsASN1 = versionAsASN1;
        return this;
    }

    public LogMessageBuilder setVersionAsASN1ToNull() {
        this.versionAsASN1 = null;
        return this;
    }

    public DEROctetString getSerialNumberAsASN1() {
        return serialNumberAsASN1;
    }

    public LogMessageBuilder setSerialNumberAsASN1(DEROctetString serialNumberAsASN1) {
        this.serialNumberAsASN1 = serialNumberAsASN1;
        return this;
    }

    public LogMessageBuilder setSerialNumberAsASN1ToNull() {
        this.serialNumberAsASN1 = null;
        return this;
    }

    public ASN1EncodableVector getSignatureAlgorithmElementsList() {
        return signatureAlgorithmElementsList;
    }

    public LogMessageBuilder setSignatureAlgorithmElementsList(ASN1EncodableVector signatureAlgorithmElementsList) {
        this.signatureAlgorithmElementsList = signatureAlgorithmElementsList;
        return this;
    }

    public ASN1ObjectIdentifier getSignatureAlgorithmAsASN1() {
        return signatureAlgorithmAsASN1;
    }

    public LogMessageBuilder setSignatureAlgorithmAsASN1(ASN1ObjectIdentifier signatureAlgorithmAsASN1) {
        this.signatureAlgorithmAsASN1 = signatureAlgorithmAsASN1;
        return this;
    }

    public ASN1Integer getSignatureCounterAsASN1() {
        return signatureCounterAsASN1;
    }

    public LogMessageBuilder setSignatureCounterAsASN1(ASN1Integer signatureCounterAsASN1) {
        this.signatureCounterAsASN1 = signatureCounterAsASN1;
        return this;
    }

    public ASN1Integer getLogTimeUnixTimeAsASN1() {
        return logTimeUnixTimeAsASN1;
    }

    public LogMessageBuilder setLogTimeUnixTimeAsASN1(ASN1Integer logTimeUnixTimeAsASN1) {
        this.logTimeUnixTimeAsASN1 = logTimeUnixTimeAsASN1;
        return this;
    }

    public LogMessageBuilder setLogTimeUnixTimeAsASN1ToNull() {
        this.logTimeUnixTimeAsASN1 = null;
        return this;
    }

    public ASN1UTCTime getLogTimeUTCAsASN1() {
        return logTimeUTCAsASN1;
    }

    public LogMessageBuilder setLogTimeUTCAsASN1(ASN1UTCTime logTimeUTCAsASN1) {
        this.logTimeUTCAsASN1 = logTimeUTCAsASN1;
        return this;
    }

    public LogMessageBuilder setLogTimeUTCAsASN1ToNull() {
        this.logTimeUTCAsASN1 = null;
        return this;
    }

    public ASN1GeneralizedTime getLogTimeGeneralizedTimeAsASN1() {
        return logTimeGeneralizedTimeAsASN1;
    }

    public LogMessageBuilder setLogTimeGeneralizedTimeAsASN1(ASN1GeneralizedTime logTimeGeneralizedTimeAsASN1) {
        this.logTimeGeneralizedTimeAsASN1 = logTimeGeneralizedTimeAsASN1;
        return this;
    }

    public LogMessageBuilder setLogTimeGeneralizedTimeAsASN1ToNull(ASN1GeneralizedTime logTimeGeneralizedTimeAsASN1) {
        this.logTimeGeneralizedTimeAsASN1 = null;
        return this;
    }

    public ASN1OctetString getSeAuditDataAsASN1() {
        return seAuditDataAsASN1;
    }

    public LogMessageBuilder setSeAuditDataAsASN1(ASN1OctetString seAuditDataAsASN1) {
        this.seAuditDataAsASN1 = seAuditDataAsASN1;
        return this;
    }

    public LogMessageBuilder setSeAuditDataAsASN1ToNull() {
        this.seAuditDataAsASN1 = null;
        return this;
    }

    public ASN1ObjectIdentifier getCertifiedDataTypeAsASN1() {
        return certifiedDataTypeAsASN1;
    }

    public LogMessageBuilder setCertifiedDataTypeAsASN1(ASN1ObjectIdentifier certifiedDataTypeAsASN1) {
        this.certifiedDataTypeAsASN1 = certifiedDataTypeAsASN1;
        return this;
    }

    public LogMessageBuilder setCertifiedDataTypeAsASN1ToNull() {
        this.certifiedDataTypeAsASN1 = null;
        return this;
    }

    public ASN1OctetString getCertifiedDataAsASN1() {
        return certifiedDataAsASN1;
    }

    public LogMessageBuilder setCertifiedDataAsASN1(ASN1OctetString certifiedDataAsASN1) {
        this.certifiedDataAsASN1 = certifiedDataAsASN1;
        return this;
    }
    public LogMessageBuilder setCertifiedDataAsASN1ToNull(ASN1OctetString certifiedDataAsASN1) {
        this.certifiedDataAsASN1 = null;
        return this;
    }

    public ASN1OctetString getSignatureValueAsASN1() {
        return signatureValueAsASN1;
    }

    public LogMessageBuilder setSignatureValueAsASN1(ASN1OctetString signatureValueAsASN1) {
        this.signatureValueAsASN1 = signatureValueAsASN1;
        return this;
    }

    public LogMessageBuilder setSignatureValueAsASN1ToNull() {
        this.signatureValueAsASN1 = null;
        return this;
    }

    public byte[] getVersionEncoded() {
        return versionEncoded;
    }

    public LogMessageBuilder setVersionEncoded(byte[] versionEncoded) {
        this.versionEncoded = versionEncoded;
        return this;
    }

    public byte[] getCertifiedDataTypeEndcoded() {
        return certifiedDataTypeEndcoded;
    }

    public LogMessageBuilder setCertifiedDataTypeEndcoded(byte[] certifiedDataTypeEndcoded) {
        this.certifiedDataTypeEndcoded = certifiedDataTypeEndcoded;
        return this;
    }

    public byte[] getCertifiedDataEncoded() {
        return certifiedDataEncoded;
    }

    public LogMessageBuilder setCertifiedDataEncoded(byte[] certifiedDataEncoded) {
        this.certifiedDataEncoded = certifiedDataEncoded;
        return this;
    }

    public byte[] getSerialNumberEncoded() {
        return serialNumberEncoded;
    }

    public LogMessageBuilder setSerialNumberEncoded(byte[] serialNumberEncoded) {
        this.serialNumberEncoded = serialNumberEncoded;
        return this;
    }

    public byte[] getSignatureAlgorithmEncoded() {
        return signatureAlgorithmEncoded;
    }

    public LogMessageBuilder setSignatureAlgorithmEncoded(byte[] signatureAlgorithmEncoded) {
        this.signatureAlgorithmEncoded = signatureAlgorithmEncoded;
        return this;
    }

    public byte[] getSeAuditDataEncoded() {
        return seAuditDataEncoded;
    }

    public LogMessageBuilder setSeAuditDataEncoded(byte[] seAuditDataEncoded) {
        this.seAuditDataEncoded = seAuditDataEncoded;
        return this;
    }

    public byte[] getSignatureCounterEncoded() {
        return signatureCounterEncoded;
    }

    public LogMessageBuilder setSignatureCounterEncoded(byte[] signatureCounterEncoded) {
        this.signatureCounterEncoded = signatureCounterEncoded;
        return this;
    }

    public byte[] getLogTimeUnixTimeEncoded() {
        return logTimeUnixTimeEncoded;
    }

    public LogMessageBuilder setLogTimeUnixTimeEncoded(byte[] logTimeUnixTimeEncoded) {
        this.logTimeUnixTimeEncoded = logTimeUnixTimeEncoded;
        return this;
    }

    public byte[] getLogTimeUTCEncoded() {
        return logTimeUTCEncoded;
    }

    public LogMessageBuilder setLogTimeUTCEncoded(byte[] logTimeUTCEncoded) {
        this.logTimeUTCEncoded = logTimeUTCEncoded;
        return this;
    }

    public byte[] getLogTimeGeneralizedTimeEncoded() {
        return logTimeGeneralizedTimeEncoded;
    }

    public LogMessageBuilder setLogTimeGeneralizedTimeEncoded(byte[] logTimeGeneralizedTimeEncoded) {
        this.logTimeGeneralizedTimeEncoded = logTimeGeneralizedTimeEncoded;
        return this;
    }

    int version = 2;
    oid certifiedDataType;
    ArrayList<ASN1Primitive> certifiedData = new ArrayList<>();
    byte[] serialNumber = "HelloWorld".getBytes(StandardCharsets.UTF_8);
    String signatureAlgorithm = "0.4.0.127.0.7.1.1.4.1.3";
    ArrayList<ASN1Primitive> signatureAlgorithmParameters = new ArrayList<>();
    String logTimeType = "unixTime";
    String logTimeUTC = "";
    String logTimeGeneralizedTime = "";
    long logTimeUnixTime = Instant.now().getEpochSecond();
    byte[] signatureValue = null;
    BigInteger signatureCounter = new BigInteger(64, new Random());
    byte[] seAuditData = null;
    byte[] dtbs = null;
    String filename = "";

    ASN1EncodableVector logMessageVector = new ASN1EncodableVector();
    ASN1Integer versionAsASN1;
    DEROctetString serialNumberAsASN1;
    ASN1EncodableVector signatureAlgorithmElementsList = new ASN1EncodableVector();
    ASN1ObjectIdentifier signatureAlgorithmAsASN1;

    ASN1Integer signatureCounterAsASN1;
    ASN1Integer logTimeUnixTimeAsASN1;
    ASN1UTCTime logTimeUTCAsASN1;
    ASN1GeneralizedTime logTimeGeneralizedTimeAsASN1;
    ASN1OctetString seAuditDataAsASN1;
    ASN1ObjectIdentifier certifiedDataTypeAsASN1;
    ASN1OctetString certifiedDataAsASN1;
    ASN1OctetString signatureValueAsASN1;

    byte[] versionEncoded;
    byte[] certifiedDataTypeEndcoded;
    byte[] certifiedDataEncoded;
    byte[] serialNumberEncoded;
    byte[] signatureAlgorithmEncoded;
    byte[] seAuditDataEncoded;
    byte[] signatureCounterEncoded;
    byte[] logTimeUnixTimeEncoded;
    byte[] logTimeUTCEncoded;
    byte[] logTimeGeneralizedTimeEncoded;


    public String getFilename() {
        return filename;
    }

    /******************************************************************
     * Abstrakte Basisclasse, um LogMessages zum Testen zu Ereugen
     * Jede Log Message muss den Lebenszyklus aus
     *  1) prepare
     *  2) calculateDTBS
     *  3) sign
     *  4) build
     *  6) ExportLogMessageToFolder oder finalizeMessage
     *  durchlaufen
     ******************************************************************/

    LogMessageBuilder prepare() throws TestLogMessageCreationError {

        try {
            versionAsASN1 = new ASN1Integer(version);
            versionEncoded = getEncodedValue(versionAsASN1);

            //certifiedDataType will be set by subclasses
            //certifiedData will be set by subclasses

            serialNumberAsASN1 = new DEROctetString(serialNumber);
            serialNumberEncoded = getEncodedValue(serialNumberAsASN1);

            signatureAlgorithmAsASN1 = new ASN1ObjectIdentifier(signatureAlgorithm);
            signatureAlgorithmEncoded = getEncodedValue(signatureAlgorithmAsASN1);
            //fixme: im moment keine parameter für den algorithmus
            signatureAlgorithmElementsList.add(signatureAlgorithmAsASN1);
            //seAuditData filled by subclass
            signatureCounterAsASN1 = new ASN1Integer(signatureCounter);
            signatureCounterEncoded = getEncodedValue(signatureCounterAsASN1);

            //logtime
            switch (logTimeType) {
                case "unixTime":
                    logTimeUnixTimeAsASN1 = new ASN1Integer(logTimeUnixTime);
                    logTimeUnixTimeEncoded = getEncodedValue(logTimeUnixTimeAsASN1);
                    break;
                case "utcTime":
                    DateFormat uTCTimeFormat = new SimpleDateFormat();
                    logTimeUTCAsASN1 = new ASN1UTCTime(uTCTimeFormat.parse(logTimeUTC));
                    logTimeUTCEncoded = getEncodedValue(logTimeUTCAsASN1);
                    break;
                case "generalizedTime":
                    DateFormat generalizedTimeFormat = new SimpleDateFormat();
                    logTimeGeneralizedTimeAsASN1 = new ASN1GeneralizedTime(generalizedTimeFormat.parse(logTimeGeneralizedTime));
                    logTimeGeneralizedTimeEncoded = getEncodedValue(logTimeGeneralizedTimeAsASN1);
                    break;
            }
        }
        catch (Exception e) {
            throw new TestLogMessageCreationError("Fehler bei der Vorbereitung der Nachricht", e);
        }
        return this;

    }


    LogMessageBuilder calculateDTBS() throws TestLogMessageCreationError {

        try (ByteArrayOutputStream dtbsStream = new ByteArrayOutputStream()) {

            if (versionEncoded != null) dtbsStream.write(versionEncoded);
            if (certifiedDataTypeEndcoded != null)   dtbsStream.write(certifiedDataTypeEndcoded);
            if (certifiedDataEncoded != null) dtbsStream.write(certifiedDataEncoded);

            if (serialNumberEncoded != null) dtbsStream.write(serialNumberEncoded);
            if (signatureAlgorithmEncoded != null) dtbsStream.write(signatureAlgorithmEncoded);
            if (seAuditDataEncoded != null) dtbsStream.write(seAuditDataEncoded);

            if (signatureCounterAsASN1 != null) dtbsStream.write(getEncodedValue(signatureCounterAsASN1));

            switch (logTimeType) {
                case "unixTime":
                    dtbsStream.write(logTimeUnixTimeEncoded);
                    break;
                case "utcTime":
                    dtbsStream.write(logTimeUTCEncoded);
                    break;
                case "generalizedTime":
                    dtbsStream.write(logTimeGeneralizedTimeEncoded);
                    break;
            }

            this.dtbs = dtbsStream.toByteArray();
        } catch (IOException | Utilities.ExtendLengthValueExceedsInteger e) {
            throw new TestLogMessageCreationError("Fehler beim Erstellen des DTBS", e);
        }

        return this;

    }
    LogMessageBuilder sign(PrivateKey key) throws TestLogMessageCreationError {
        Signature signer = null;
        try {
            signer = Signature.getInstance(signatureAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new TestLogMessageCreationError("Fehler beim der Erstellung der Signatur", e);
        }
        try {
            signer.initSign(key);
        } catch (InvalidKeyException e) {
            throw new TestLogMessageCreationError("Fehler beim der Erstellung der Signatur. Ungültiger Schlüssel", e);
        }
        try {
            signer.update(dtbs);
            signatureValue = signer.sign();
            signatureValueAsASN1 = new DEROctetString(signatureValue);

        } catch (SignatureException e) {
            throw new TestLogMessageCreationError("Fehler beim der Erstellung der Signatur", e);
        }
        return this;
    }


    LogMessageBuilder build() {
        if (versionAsASN1 != null) logMessageVector.add(versionAsASN1);
        if (certifiedDataTypeAsASN1 != null) logMessageVector.add(certifiedDataTypeAsASN1);
        if (certifiedDataAsASN1 != null) logMessageVector.add(certifiedDataAsASN1);
        if (serialNumberAsASN1 != null) logMessageVector.add(serialNumberAsASN1);
        //fixme: im moment keine parameter für den algorithmus
        if (signatureAlgorithmElementsList != null)
            logMessageVector.add(new DERSequence(signatureAlgorithmElementsList));
        if (seAuditDataAsASN1 != null) logMessageVector.add(seAuditDataAsASN1);
        if (signatureAlgorithmAsASN1 != null) logMessageVector.add(signatureCounterAsASN1);

        switch (logTimeType) {
            case "unixTime":
                logMessageVector.add(logTimeUnixTimeAsASN1);
                break;
            case "utcTime":
                logMessageVector.add(logTimeUTCAsASN1);
                break;
            case "generalizedTime":
                logMessageVector.add(logTimeGeneralizedTimeAsASN1);
                break;
        }
        logMessageVector.add(signatureValueAsASN1);
        return this;

    }

    public byte[] finalizeMessage() {
        filename = constructFileName();
        byte[] message = null;
        DERSequence messageSequenceForExport = new DERSequence(logMessageVector);
        try {
            message = messageSequenceForExport.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return message;
    }

    public String exportLogMessageToFolder(String exportFolder) throws TestLogMessageExportError {
        filename = constructFileName();
        DERSequence messageSequenceForExport = new DERSequence(logMessageVector);
        Path exportPath = Paths.get(exportFolder, filename);

        try {
            Files.write(exportPath, messageSequenceForExport.getEncoded());
        } catch (IOException e) {
            throw new TestLogMessageExportError("Fehler beim Export der Message", e);
        }
        return filename;
    }

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
        filename = filename + "_Log-Aud.log";
        return filename;
    }



    public class TestLogMessageCreationError extends Exception {
        public TestLogMessageCreationError(String message, Exception reason) {
            super(message, reason);
        }
    }
    public class TestLogMessageExportError extends Exception {
        public TestLogMessageExportError(String message, Exception reason) {
            super(message, reason);
        }
    }
}


