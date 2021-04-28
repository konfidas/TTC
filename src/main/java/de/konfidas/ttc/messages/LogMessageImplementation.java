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
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.text.ParseException;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Diese Klasse repräsentiert eine LogMessage. Der Konstruktur erhält den Inhalt der LogMessage und den Dateinamen, aus der
 * die LogMessage gelesen wurde. Die LogMessage wird geparst. Dabei wird das folgende Format erwartet
 * // ╔═══════════════════════╤══════╤══════════════════════════════════╤════════════╗
 * // ║ Data field            │ Tag  │ Data Type                        │ Mandatory? ║
 * // ╠═══════════════════════╪══════╪══════════════════════════════════╪════════════╣
 * // ║ LogMessage            │ 0x30 │ SEQUENCE                         │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    version            │ 0x02 │ INTEGER                          │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    certifiedDataType  │ 0x06 │ OBJECT IDENTIFIER                │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    certifiedData      │      │ ANY DEFINED BY certifiedDataType │ o          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    serialNumber       │ 0x04 │ OCTET STRING                     │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    signatureAlgorithm │ 0x30 │ SEQUENCE                         │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       algorithm       │ 0x06 │ OBJECT IDENTIFIER                │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       parameters      │      │ ANY DEFINED BY algorithm         │ o          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    seAuditData        │ 0x04 │ OCTET STRING                     │ c          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    signatureCounter   │ 0x02 │ INTEGER                          │ c          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    logTime            │      │ CHOICE                           │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       utcTime         │ 0x17 │ UTCTime                          │            ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       generalizedTime │ 0x18 │ GeneralizedTime                  │            ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       unixTime        │ 0x02 │ INTEGER                          │            ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    signatureValue     │ 0x04 │ OCTET STRING                     │ m          ║
 * // ╚═══════════════════════╧══════╧══════════════════════════════════╧════════════╝
 */
public abstract class LogMessageImplementation implements LogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    final static String[] allowedCertifiedDataType = {"0.4.0.127.0.7.3.7.1.1", "0.4.0.127.0.7.3.7.1.2", "0.4.0.127.0.7.3.7.1.3"};
    final static String[] allowedAlgorithms = {"0.4.0.127.0.7.1.1.4.1.2", "0.4.0.127.0.7.1.1.4.1.3", "0.4.0.127.0.7.1.1.4.1.4", "0.4.0.127.0.7.1.1.4.1.5", "0.4.0.127.0.7.1.1.4.1.8", "0.4.0.127.0.7.1.1.4.1.9", "0.4.0.127.0.7.1.1.4.1.10", "0.4.0.127.0.7.1.1.4.1.11", "0.4.0.127.0.7.1.1.4.4.1", "0.4.0.127.0.7.1.1.4.4.2", "0.4.0.127.0.7.1.1.4.4.3", "0.4.0.127.0.7.1.1.4.4.4", "0.4.0.127.0.7.1.1.4.4.5", "0.4.0.127.0.7.1.1.4.4.6", "0.4.0.127.0.7.1.1.4.4.7", "0.4.0.127.0.7.1.1.4.4.8"};

    int version = 0;
    oid certifiedDataType;
    final ArrayList<ASN1Primitive> certifiedData = new ArrayList<>();
    byte[] serialNumber;
    String signatureAlgorithm = "";
    final ArrayList<ASN1Primitive> signatureAlgorithmParameters = new ArrayList<>();

    LogTime logTime;

    byte[] signatureValue = null;
    BigInteger signatureCounter = new BigInteger("5");
    byte[] seAuditData = null;
    byte[] dtbs = null;
    final String filename;


    public LogMessageImplementation(File file) throws IOException, BadFormatForLogMessageException {
        this(Files.readAllBytes(file.toPath()), file.getName());
    }

    public LogMessageImplementation(byte[] content, String filename) throws BadFormatForLogMessageException {
        this.filename = filename;
        parse(content);
        checkContent();
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
                throw new ExtendLengthValueExceedsInteger("Der Wert der extended length überschreitet einen Integer", null);
            }

            byte[] lengthBytesFromElement = Arrays.copyOfRange(elementContent, 2, 2+elementNumberOfLengthBytes); //we need to have 4 bytes for an integer
            byte[] prependBytes = new byte[4-elementNumberOfLengthBytes];

            ByteBuffer lengthByte = ByteBuffer.wrap(new byte[4]);
            lengthByte.put(prependBytes);
            lengthByte.put(lengthBytesFromElement);
            return lengthByte.getInt(0);
        }
    }

    byte[] getEncodedValue(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger {
        byte[] elementContent = element.getEncoded();
        int elementLength = this.getEncodedLength(element);
        return Arrays.copyOfRange(elementContent, elementContent.length - elementLength, elementContent.length + 1);
    }

    int getEncodedTag(ASN1Primitive element) throws IOException {
        byte[] elementContent = element.getEncoded();
        return elementContent[0];
    }

    void parse(byte[] content) throws LogMessageParsingException {
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
            throw new LogMessageParsingException("failed to parse log message", e);
        }
    }

    private void parseVersionNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("Version element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)) {
            throw new LogMessageParsingException("vesrion has to be ASN1Integer, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();
        this.version = ((ASN1Integer) element).intValueExact();
        dtbsStream.write(this.getEncodedValue(element));
    }

    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("certifidDataype element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1ObjectIdentifier)) {
            throw new LogMessageParsingException("certifidData#Type has to be ASN1ObjectIdentifier, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        try { this.certifiedDataType = oid.fromBytes(element.getEncoded()); } catch (oid.UnknownOidException e) {
            throw new CertifiedDataTypeParsingException("OID for certifiedData unknown", e);
        }
        dtbsStream.write(this.getEncodedValue(element));

    }

    private void parseSerialNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("serialNumber element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1OctetString)) {
            throw new LogMessageParsingException("serialNumber has to be ASN1OctetString, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        this.serialNumber = ((ASN1OctetString) element).getOctets();
        dtbsStream.write(this.serialNumber);

    }

    private void parseSignatureAlgorithm(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) {
            throw new LogMessageParsingException("aignatureAlgorithm element not found");
        }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Sequence)) {
            throw new LogMessageParsingException("aignatureAlgorithm has to be ASN1Sequence, but is " + nextElement.getClass());
        }

        ASN1Primitive element = logMessageIterator.next();

        Enumeration<ASN1Primitive> sigAlgorithmEnumeration = ((ASN1Sequence) element).getObjects();

        element = sigAlgorithmEnumeration.nextElement();
        // Erst lesen wir den signatureAlgorihtm selbst

        if (element instanceof ASN1ObjectIdentifier) {
            this.signatureAlgorithm = element.toString();
            dtbsStream.write(this.getEncodedValue(element));

            if (!Arrays.asList(allowedAlgorithms).contains(this.signatureAlgorithm)) {
                throw new LogMessageParsingException(String.format("Die OID für signatureAlgorithm lautet %s. Dies ist keine erlaubte OID", this.signatureAlgorithm));
            }


            //Dann eine Schleife über den Rest für die SignatureAlgorithmParameters
            while (sigAlgorithmEnumeration.hasMoreElements()) {
                element = sigAlgorithmEnumeration.nextElement();
                this.signatureAlgorithmParameters.add(element);
            }

        } else {
            throw new LogMessageParsingException("Die Sequenz für den signatureAlgortihm wurde nicht gefunden.");
        }

    }

    abstract void parseSeAuditData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException;


    private void parseSignatureCounter(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("signatureCounter element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)) { throw new LogMessageParsingException("signatureCounter has to be ASN1Integer, but is " + nextElement.getClass()); }

        ASN1Primitive element = logMessageIterator.next();
        this.signatureCounter = ((ASN1Integer) element).getValue();
        dtbsStream.write(this.getEncodedValue(element));

    }


    private void parseTime(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws IOException, LogMessageParsingException, ParseException {
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("logTime element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)&& !(nextElement instanceof ASN1UTCTime) && !(nextElement instanceof ASN1GeneralizedTime)) { throw new LogMessageParsingException("logTime is of invalid type. It is " + nextElement.getClass()); }

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
        if (!logMessageIterator.hasNext()) { throw new LogMessageParsingException("signature element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1OctetString)) { throw new LogMessageParsingException("signature has to be ASN1OctetString, but is " + nextElement.getClass()); }

        ASN1Primitive element = logMessageIterator.next();
        this.signatureValue = ((ASN1OctetString) element).getOctets();
        dtbsStream.write(this.getEncodedValue(element));

    }


    abstract void parseCertifiedData(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException;

    void checkContent() throws LogMessageParsingException {
        // Die Versionsnummer muss 2 sein
        if (this.version != 2) {
            throw new LogMessageParsingException("Die Versionsnummer ist nicht 2");
        }

        // TODO: no longer required here. Done as part of parsing.
        // Prüfen, dass der certifiedDataType ein erlaubter Wert ist
        if (!Arrays.asList(allowedCertifiedDataType).contains(this.certifiedDataType.getReadable())) {
            throw new LogMessageParsingException(String.format("Der Wert von certifiedDataType ist nicht erlaubt. er lautet %s", this.certifiedDataType));
        }

        // Prüfen, dass die Serial Number auch da ist.
        if (this.serialNumber == null) {
            throw new LogMessageParsingException("Die Serial Number ist null");
        }

        // Und die Signatur muss auch da sein

        if (this.signatureValue == null) {
            throw new LogMessageParsingException("LogMessage ohne Signatur");
        }

        if (logTime == null) {
            throw new LogMessageParsingException("Es ist kein Typ für die LogZeit vorhanden");
        }
    }

    public class LogMessageParsingException extends BadFormatForLogMessageException {
        public LogMessageParsingException(String message) {
            super("Parsing Message " + filename + " failed: " + message, null);
        }

        public LogMessageParsingException(String message, Exception reason) {
            super("Parsing Message " + filename + " failed: " + message, reason);
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
}


