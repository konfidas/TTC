package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.utilities.oid;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;

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
    ASN1Primitive operationType;
    ASN1Primitive systemOperationData;
    ASN1Primitive additionalInternalData;


    public UnblockUserSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
    void parseSystemOperationDataContent(DLTaggedObject element) throws SystemLogParsingException, IOException {

        //TODO: @DH: Kannst Du hier mal schauen?
        Class tttt = element.getClass();
        DERSet set = (DERSet) DERSet.getInstance(element,false);
//



    }


}
