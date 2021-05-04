package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLTaggedObject;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


/**
 * Diese Klasse repräsentiert eine authenticateUserSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ userID                │ 0x81 │ PrintableString                                               │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ role                  │ 0x82 │ ENUMERATED{ admin, timeAdmin }                                │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ authenticationResult  │ 0x83 │ BOOLEAN                                                       │ m          ║
 * ╚═══════════════════════╧══════╧══════════════════════════════════╧═════════════════════════════════════════╝
 * </pre>
 */
public class AuthenticateUserSystemLogMessage extends SystemLogMessage {
    public DLTaggedObject getUserId() {
        return userId;
    }

    public void setUserId(DLTaggedObject userId) {
        this.userId = userId;
    }

    public DLTaggedObject getRole() {
        return role;
    }

    public void setRole(DLTaggedObject role) {
        this.role = role;
    }

    public DLTaggedObject getAuthenticationResult() {
        return authenticationResult;
    }

    public void setAuthenticationResult(DLTaggedObject authenticationResult) {
        this.authenticationResult = authenticationResult;
    }

    public String getUserIDAsString() {
        return userIDAsString;
    }

    public void setUserIDAsString(String userIDAsString) {
        this.userIDAsString = userIDAsString;
    }

    public BigInteger getRoleAsBigInteger() {
        return roleAsBigInteger;
    }

    public void setRoleAsBigInteger(BigInteger roleAsBigInteger) {
        this.roleAsBigInteger = roleAsBigInteger;
    }

    public boolean isAuthenticationResultAsBoolean() {
        return authenticationResultAsBoolean;
    }

    public void setAuthenticationResultAsBoolean(boolean authenticationResultAsBoolean) {
        this.authenticationResultAsBoolean = authenticationResultAsBoolean;
    }

    DLTaggedObject userId;
    DLTaggedObject role;
    DLTaggedObject authenticationResult;

    String userIDAsString;
    BigInteger roleAsBigInteger;
    boolean authenticationResultAsBoolean;

    public AuthenticateUserSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
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

            //role einlesen
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 2) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld role wurde nicht gefunden");

            this.role = (DLTaggedObject) systemOperationDataIterator.next();
            this.roleAsBigInteger = DLTaggedObjectConverter.dLTaggedObjectFromEnumerationToBigInteger(this.role);

            //authenticationResult einlesen
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 3) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld authenticationResult wurde nicht gefunden");

            this.authenticationResult = (DLTaggedObject) systemOperationDataIterator.next();
            this.authenticationResultAsBoolean = DLTaggedObjectConverter.dLTaggedObjectToBoolean(this.authenticationResult);

        }
        catch (NoSuchElementException ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
        }

    }


}