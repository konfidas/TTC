package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.utilities.oid;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;
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
    ASN1Primitive userId;
    ASN1Primitive unblockResult;


    public UnblockUserSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


//    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogMessage.SystemLogParsingException, IOException {
        userId = stream.readObject();
        unblockResult = stream.readObject();
    }


}