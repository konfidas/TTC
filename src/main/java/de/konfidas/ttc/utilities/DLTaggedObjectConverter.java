package de.konfidas.ttc.utilities;

import org.bouncycastle.asn1.*;

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

    public static Boolean dLTaggedObjectToBoolean(DLTaggedObject object){

        ASN1Primitive objectAsn1Primitive = object.getObject();
        //TODO: testen, dass das folgende funktioniert
        return (((DEROctetString)objectAsn1Primitive).getOctets()[0]==0);
    }

}
