package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;


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
    ASN1Primitive userId;
    ASN1Primitive role;
    ASN1Primitive authenticationResult;


    public AuthenticateUserSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {

        try{
        userId = stream.readObject();
        role = stream.readObject();
        authenticationResult = stream.readObject();
    }
        catch (Exception ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent",ex);
        }
    }


}