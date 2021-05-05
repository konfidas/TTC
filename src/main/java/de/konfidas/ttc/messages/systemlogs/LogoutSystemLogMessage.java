package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


/**
 * Diese Klasse repräsentiert eine logoutSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ userID                │ 0x81 │ PrintableString                                               │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ logOutCause           │ 0x82 │ ENUMERATED{ user, timeout }                                   │ m          ║
 * ╚═══════════════════════╧══════╧═══════════════════════════════════════════════════════════════╧════════════╝
 * </pre>
 */
public class LogoutSystemLogMessage extends SystemLogMessage {
    public DLTaggedObject getUserId() {
        return userId;
    }

    public void setUserId(DLTaggedObject userId) {
        this.userId = userId;
    }

    public DLTaggedObject getLogoutCause() {
        return logoutCause;
    }

    public void setLogoutCause(DLTaggedObject logoutCause) {
        this.logoutCause = logoutCause;
    }

    public String getUserIDAsString() {
        return userIDAsString;
    }

    public void setUserIDAsString(String userIDAsString) {
        this.userIDAsString = userIDAsString;
    }

    public BigInteger getLogoutCauseAsBigInteger() {
        return logoutCauseAsBigInteger;
    }

    public void setLogoutCauseAsBigInteger(BigInteger logoutCauseAsBigInteger) {
        this.logoutCauseAsBigInteger = logoutCauseAsBigInteger;
    }

    DLTaggedObject userId;
    DLTaggedObject logoutCause;

    String userIDAsString;
    BigInteger logoutCauseAsBigInteger;




    public LogoutSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
        protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {

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

            //logoutCause einlesen
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 2)throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld logoutCause wurde nicht gefunden");

                this.logoutCause = (DLTaggedObject) systemOperationDataIterator.next();
                this.logoutCauseAsBigInteger = DLTaggedObjectConverter.dLTaggedObjectFromEnumerationToBigInteger(this.logoutCause);



        }
        catch (NoSuchElementException ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
        }
    }


}