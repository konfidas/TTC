package de.konfidas.ttc.messages;

import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;

import java.io.File;
import java.io.IOException;
import java.math.*;
import java.nio.file.Files;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Diese Klasse repräsentiert eine LogMessage. Der Konstruktur erhält den Inhalt der LogMessage und den Dateinamen, aus der
 * die LogMessage gelesen wurde. Die LogMessage wird geparst. Dabei wird das folgende Format erwartet
 * <pre>
 * ╔═══════════════════════╤══════╤══════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                        │ Mandatory? ║
 * ╠═══════════════════════╪══════╪══════════════════════════════════╪════════════╣
 * ║ LogMessage            │ 0x30 │ SEQUENCE                         │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    version            │ 0x02 │ INTEGER                          │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    certifiedDataType  │ 0x06 │ OBJECT IDENTIFIER                │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    certifiedData      │      │ ANY DEFINED BY certifiedDataType │ o          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    serialNumber       │ 0x04 │ OCTET STRING                     │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    signatureAlgorithm │ 0x30 │ SEQUENCE                         │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║       algorithm       │ 0x06 │ OBJECT IDENTIFIER                │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║       parameters      │      │ ANY DEFINED BY algorithm         │ o          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    seAuditData        │ 0x04 │ OCTET STRING                     │ c          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    signatureCounter   │ 0x02 │ INTEGER                          │ c          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    logTime            │      │ CHOICE                           │ m          ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║       utcTime         │ 0x17 │ UTCTime                          │            ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║       generalizedTime │ 0x18 │ GeneralizedTime                  │            ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║       unixTime        │ 0x02 │ INTEGER                          │            ║
 * ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * ║    signatureValue     │ 0x04 │ OCTET STRING                     │ m          ║
 * ╚═══════════════════════╧══════╧══════════════════════════════════╧════════════╝
 * </pre>
 */
public abstract class LogMessageImplementation implements LogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS


    final static String[] allowedCertifiedDataType = {"0.4.0.127.0.7.3.7.1.1", "0.4.0.127.0.7.3.7.1.2", "0.4.0.127.0.7.3.7.1.3"};
    final static String[] allowedAlgorithms = {"0.4.0.127.0.7.1.1.4.1.2", "0.4.0.127.0.7.1.1.4.1.3", "0.4.0.127.0.7.1.1.4.1.4", "0.4.0.127.0.7.1.1.4.1.5", "0.4.0.127.0.7.1.1.4.1.8", "0.4.0.127.0.7.1.1.4.1.9", "0.4.0.127.0.7.1.1.4.1.10", "0.4.0.127.0.7.1.1.4.1.11", "0.4.0.127.0.7.1.1.4.4.1", "0.4.0.127.0.7.1.1.4.4.2", "0.4.0.127.0.7.1.1.4.4.3", "0.4.0.127.0.7.1.1.4.4.4", "0.4.0.127.0.7.1.1.4.4.5", "0.4.0.127.0.7.1.1.4.4.6", "0.4.0.127.0.7.1.1.4.4.7", "0.4.0.127.0.7.1.1.4.4.8"};

    int version = 0;
    oid certifiedDataType;
    final ArrayList<ASN1Primitive> certifiedData = new ArrayList<>();
    byte[] serialNumber;
    String signatureAlgorithm = "";
    final ArrayList<ASN1Primitive> signatureAlgorithmParameters = new ArrayList<>();

    LogTime logTime;

    byte[] encoded;
    byte[] signatureValue;
    BigInteger signatureCounter = new BigInteger("5");
    byte[] seAuditData;
    byte[] dtbs;
    final String filename;


    public LogMessageImplementation(File file) throws IOException, BadFormatForLogMessageException {
        this(Files.readAllBytes(file.toPath()), file.getName());
    }

    public LogMessageImplementation(byte[] content, String filename) throws BadFormatForLogMessageException {
        this.filename = filename;
        parse(content);
    }

    /**
     * @return die toString Methode wurde überschrieben. Sie gibt den Dateinamen zurück, aus dem die LogMessage stammt
     */
    public String toString() {
        return this.filename;
    }

    @Override
    public byte[] getSerialNumber() {
        return this.serialNumber;
    }

    @Override
    public String getFileName() {
        return this.filename;
    }

    @Override
    public byte[] getSignatureValue() {
        return this.signatureValue;
    }

    @Override
    public byte[] getDTBS() {
        return this.dtbs;
    }

    @Override
    public byte[] getSeAuditData() {
        return this.seAuditData;
    }

    @Override
    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    @Override
    public LogTime getLogTime(){return logTime; }

    @Override
    public BigInteger getSignatureCounter() { return signatureCounter; }

    @Override
    public Collection<ASN1Primitive> getSignatureAlgorithmParameters(){
        return this.signatureAlgorithmParameters;
    }

    @Override
    public oid getCertifiedDataType(){
        return this.certifiedDataType;
    }

    @Override
    public int getVersion(){
        return version;
    }

    /**
     * Diese Funktion gibt die Lönge eines ASN1Elements als integer zurück.
     * Falls die Länge nicht in ein Integer oasst, wird ein Fehler geworfen
     * Bei indefinite lgenght encoding wir 0 zurückgegeben
     *
     * @param element
     * @return Gibt die Länge des Elements als integer zurück
     * @throws IOException
     * @throws ExtendLengthValueExceedsInteger Wird geworfen, falls element mit einer extended length kodiert ist, die mehr als 4 bytes erfordert
     */
    private int getEncodedLength(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger {
        byte[] elementContent = element.getEncoded();

        if ( elementContent[1] == (byte) 0b10000000) {
            //indefinte length encoding
            return 0;
        } else if ((elementContent[1] & 0b10000000) == 0) {
            //Case: Definite length encocding, one byte
            return elementContent[1];
        } else {
            //Extended length encoding (limitiert auf max 4 bytes für die Länge)
            int elementNumberOfLengthBytes = (elementContent[1] & 0b01111111);
            if (elementNumberOfLengthBytes > 4) {
                throw new ExtendLengthValueExceedsInteger(properties.getString("de.konfidas.ttc.messages.extendedLengthLongerThanInt"), null);
            }

            byte[] lengthBytesFromElement = Arrays.copyOfRange(elementContent, 2, 2+elementNumberOfLengthBytes); //we need to have 4 bytes for an integer
            return new BigInteger(1,lengthBytesFromElement).intValue();
        }
    }

    byte[] getEncodedValue(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger {
        byte[] elementContent = element.getEncoded();
        int elementLength = this.getEncodedLength(element);
        logger.debug(String.valueOf(elementContent.length));
        logger.debug(String.valueOf(elementLength));
        return Arrays.copyOfRange(elementContent, elementContent.length - elementLength, elementContent.length + 1);
    }

    int getEncodedTag(ASN1Primitive element) throws IOException {
        byte[] elementContent = element.getEncoded();
        return elementContent[0];
    }

    void parse(byte[] content) throws LogMessageParsingException {
        this.encoded = content;

        try (ByteArrayOutputStream dtbsStream = new ByteArrayOutputStream()) {
            final ASN1InputStream inputStreamDecoder = new ASN1InputStream(content);
            ASN1Primitive logMessageAsASN1 = inputStreamDecoder.readObject();


            if (logMessageAsASN1 instanceof ASN1Sequence) {

                List<ASN1Primitive> logMessageAsASN1List = Collections.list(((ASN1Sequence) logMessageAsASN1).getObjects());
                ListIterator<ASN1Primitive> logMessageIterator = logMessageAsASN1List.listIterator();

                //Das erste Element MUSS die versionNumber sein
                parseVersionNumber(dtbsStream, logMessageAsASN1List, logMessageIterator);
                parseCertifiedDataType(dtbsStream, logMessageAsASN1List, logMessageIterator);

                parseCertifiedData(dtbsStream, logMessageAsASN1List, logMessageIterator);

                //FIXME: Dieser Teil des Parsers ist tricky. Wir gehen aktuell davon aus, dass wenn certifiedDataType gesetzt ist, dass dann auch certifiedData vorhanden ist. Aber hier gibt es einige
                //theoretische Fälle, die Probleme machen können.

                parseSerialNumber(dtbsStream, logMessageAsASN1List, logMessageIterator);
                parseSignatureAlgorithm(dtbsStream, logMessageAsASN1List, logMessageIterator);
                parseSeAuditData(dtbsStream, logMessageAsASN1List, logMessageIterator);


                parseSignatureCounter(dtbsStream, logMessageAsASN1List, logMessageIterator);
                parseTime(dtbsStream, logMessageAsASN1List, logMessageIterator);
                parseSignature(dtbsStream, logMessageAsASN1List, logMessageIterator);


                //Speichern des DTBS aus dem BufferedWriter
                this.dtbs = dtbsStream.toByteArray();
            }
        } catch (IOException | NoSuchElementException | ParseException e) {
            throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.failedToParseMessage"), e);
        }
    }

    private void parseVersionNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.versionElementNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)) {
            throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.versionFieldOfWrongType"), nextElement.getClass()));
        }

        ASN1Primitive element = logMessageIterator.next();
        this.version = ((ASN1Integer) element).intValueExact();
        if (this.version != 2) {
            throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.wrongVersionNumber"));
        }
        dtbsStream.write(this.getEncodedValue(element));
    }

    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.certifiedDataTypeNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1ObjectIdentifier)) {
            throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.certifiedDataTypeOfWrongType"), nextElement.getClass()));
        }

        ASN1Primitive element = logMessageIterator.next();

        try { this.certifiedDataType = oid.fromBytes(element.getEncoded()); } catch (oid.UnknownOidException e) {
            throw new CertifiedDataTypeParsingException(properties.getString("de.konfidas.ttc.messages.oidForCertifiedDataUnknown"), e);
        }
        dtbsStream.write(this.getEncodedValue(element));

    }

    private void parseSerialNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.serialNumberNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1OctetString)) {
            throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.serialNumberOfWrongType"), nextElement.getClass()));
        }

        ASN1Primitive element = logMessageIterator.next();

        this.serialNumber = ((ASN1OctetString) element).getOctets();
        dtbsStream.write(this.serialNumber);

    }

    private void parseSignatureAlgorithm(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) {
            throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.signatureAlgorithmNotFound"));
        }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Sequence)) {
            throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.signatureAlgorithmOfWrongType"), nextElement.getClass()));
        }

        ASN1Primitive element = logMessageIterator.next();

        Enumeration<ASN1Primitive> sigAlgorithmEnumeration = ((ASN1Sequence) element).getObjects();

        element = sigAlgorithmEnumeration.nextElement();
        // Erst lesen wir den signatureAlgorihtm selbst

        if (element instanceof ASN1ObjectIdentifier) {
            this.signatureAlgorithm = element.toString();
            dtbsStream.write(this.getEncodedValue(element));

            if (!Arrays.asList(allowedAlgorithms).contains(this.signatureAlgorithm)) {
                throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.invalidOIDForSignatureAlgorithm"), this.signatureAlgorithm));
            }


            //Dann eine Schleife über den Rest für die SignatureAlgorithmParameters
            while (sigAlgorithmEnumeration.hasMoreElements()) {
                element = sigAlgorithmEnumeration.nextElement();
                this.signatureAlgorithmParameters.add(element);
            }

        } else {
            throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.signatureAlgorithmSequenceNotFound"));
        }

    }

    abstract void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException;


    private void parseSignatureCounter(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.sigantureCounterNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)) { throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.sigantureCounterOfWrongType2"), nextElement.getClass())); }

        ASN1Primitive element = logMessageIterator.next();
        this.signatureCounter = ((ASN1Integer) element).getValue();
        dtbsStream.write(this.getEncodedValue(element));

    }


    private void parseTime(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws IOException, LogMessageParsingException, ParseException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.logTimeNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)&& !(nextElement instanceof ASN1UTCTime) && !(nextElement instanceof ASN1GeneralizedTime)) { throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.logTimeInvalidType"), nextElement.getClass())); }

        ASN1Primitive element = logMessageIterator.next();

        if (element instanceof ASN1Integer) {
            this.logTime = new UnixLogTime(((ASN1Integer) element).getValue().intValue());
            dtbsStream.write(this.getEncodedValue(element));
        } else if (element instanceof ASN1UTCTime) {
            this.logTime = new UtcLogTime(((ASN1UTCTime) element));
            dtbsStream.write(this.getEncodedValue(element));
        } else if (element instanceof ASN1GeneralizedTime) {
            this.logTime = new GeneralizedLogTime((ASN1GeneralizedTime) element);
            dtbsStream.write(this.getEncodedValue(element));
        }
    }

    private void parseSignature(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException(properties.getString("de.konfidas.ttc.messages.signatureNotFound")); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1OctetString)) { throw new LogMessageParsingException(String.format(properties.getString("de.konfidas.ttc.messages.signatureWrongType"), nextElement.getClass())); }

        ASN1Primitive element = logMessageIterator.next();
        this.signatureValue = ((ASN1OctetString) element).getOctets();
        dtbsStream.write(this.getEncodedValue(element));

    }


    abstract void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException;


    public class LogMessageParsingException extends BadFormatForLogMessageException {
        public LogMessageParsingException(String message) {
            super(MessageFormat.format(properties.getString("de.konfidas.ttc.messages.parsingOfMessageFailedWithReason"), filename,message, null));
        }

        public LogMessageParsingException(String message, Exception reason) {
            super(MessageFormat.format(properties.getString("de.konfidas.ttc.messages.parsingOfMessageFailedWithReason"), filename,message, reason));
        }
    }

    public class CertifiedDataTypeParsingException extends LogMessageParsingException {
        public CertifiedDataTypeParsingException(String message, Exception reason) {
            super(message, reason);
        }
    }

    public class SerialNumberParsingException extends LogMessageParsingException {
        public SerialNumberParsingException(String message, Exception reason) {
            super(message, reason);
        }
    }

    public class ExtendLengthValueExceedsInteger extends LogMessageParsingException {
        public ExtendLengthValueExceedsInteger(String message, Exception reason) {
            super(message, reason);
        }
    }


    public static class SignatureCounterComparator implements Comparator<LogMessage>{
        @Override
        public int compare(LogMessage o1, LogMessage o2) {
            return o1.getSignatureCounter().compareTo(o2.getSignatureCounter());
        }
    }

    @Override
    public byte[] getEncoded(){
        return this.encoded;
    }

    @Override
    public boolean equals(Object o){
        if(o instanceof LogMessage){
            return Arrays.equals(this.getEncoded(), ((LogMessage) o).getEncoded());
        }

        if(o instanceof byte[]){
            return Arrays.equals(this.getEncoded(), (byte[])o);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(encoded);
    }
}


