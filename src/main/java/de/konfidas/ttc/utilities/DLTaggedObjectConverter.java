package de.konfidas.ttc.utilities;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLTaggedObject;

import java.math.BigInteger;

public class DLTaggedObjectConverter {

    public static String dLTaggedObjectToString(DLTaggedObject object){
        ASN1Primitive objectAsn1Primitive = object.getObject();
        return new String(((DEROctetString)objectAsn1Primitive).getOctets());
    }

    public static BigInteger dLTaggedObjectFromEnumerationToBigInteger(DLTaggedObject object){

        ASN1Primitive objectAsn1Primitive = object.getObject();
        return new BigInteger(((DEROctetString)objectAsn1Primitive).getOctets());
    }

}
