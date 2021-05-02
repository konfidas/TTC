package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import org.bouncycastle.asn1.*;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


/**
 * Diese Klasse repräsentiert eine unblockUserSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * // ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * // ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * // ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * // ║ userID                │ 0x81 │ PrintableString                                               │ m          ║
 * // ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * // ║ unblockResult         │ 0x82 │ ENUMERATED UnblockResult{ ok, failed, unknownUserId, error }  │ m          ║
 * // ╚═══════════════════════╧══════╧══════════════════════════════════╧═════════════════════════════════════════╝
 */
public class UnblockUserSystemLogMessage extends SystemLogMessage {
    public DLTaggedObject getUserId() {
        return userId;
    }

    public DLTaggedObject getUnblockResult() {
        return unblockResult;
    }

    public String getUserIDAsString() {
        return userIDAsString;
    }

    public BigInteger getUnblockResultsAsBigInteger() {
        return unblockResultsAsBigInteger;
    }

    DLTaggedObject userId;
    DLTaggedObject unblockResult;
    String userIDAsString;
    BigInteger unblockResultsAsBigInteger;


    public UnblockUserSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogMessage.SystemLogParsingException, IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent");

            List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
            ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

            try {
                //userID einlesen
                DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
                if (nextElement.getTagNo() != 1) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld userID wurde nicht gefunden");

                this.userId = (DLTaggedObject) systemOperationDataIterator.next();
                this.userIDAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.userId);

                //unblockResult einlesen
                nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
                if (nextElement.getTagNo() != 2) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld unblockResiult wurde nicht gefunden");

                this.unblockResult = (DLTaggedObject) systemOperationDataIterator.next();
                this.unblockResultsAsBigInteger = DLTaggedObjectConverter.dLTaggedObjectFromEnumerationToBigInteger(this.unblockResult);
            }
            catch (NoSuchElementException ex){
                throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
            }


    }


}