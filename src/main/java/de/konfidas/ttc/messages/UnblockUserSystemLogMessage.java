package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
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
    void parseSystemOperationDataContent(ASN1Primitive element) throws SystemLogParsingException, IOException {

        final ASN1InputStream systemOperationDataContentDecoder = new ASN1InputStream(element.getEncoded());

        ASN1Sequence asn1 = ASN1Sequence.getInstance(systemOperationDataContentDecoder.readObject());
//        ASN1Primitive test = systemOperationDataContentDecoder.readObject();
//        ASN1Primitive test2 = systemOperationDataContentDecoder.readObject();
        int a =0;

//        DERApplicationSpecific app = (DERApplicationSpecific) systemOperationDataContentDecoder.readObject();
//        DLSequence seq = (DLSequence) systemOperationDataContentDecoder.readObject();
//        List<ASN1Primitive> logMessageAsASN1List = Collections.list(((ASN1Sequence) systemOperationDataContentDecoder.readObject()).getObjects());

//        Enumeration secEnum = seq.getObjects();
//        while (secEnum.hasMoreElements()) {
//            ASN1Primitive seqObj = (ASN1Primitive) secEnum.nextElement();
//            System.out.println(seqObj);
//        }
//

//        systemOperationDataContentDecoder.rea
//        if (!systemOperationDataContentDecoder.hasNext()) { throw new SystemLogParsingException("userID  element in parseSystemOperationData not found"); }
//        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
//        if (!(nextElement instanceof DLTaggedObject)) {
//            throw new OperationTypeParsingException("operationsType has to be DLTaggedObject, but is " + nextElement.getClass());
//        }
//
//        ASN1Primitive element = logMessageIterator.next();
//
//        int tag = ((DLTaggedObject) element).getTagNo() ;
//        if (tag != 0){
//            throw new OperationTypeParsingException("operationType not found. Expected Element [0] but got ["+tag+"]");
//        }


//        ASN1Primitive fristEntry = elementDecoder.readObject();
//        int a=0;



    }


}
