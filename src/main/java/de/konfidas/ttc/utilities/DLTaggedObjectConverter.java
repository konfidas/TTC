package de.konfidas.ttc.utilities;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class DLTaggedObjectConverter {

    public static String dLTaggedObjectToString(DLTaggedObject object){
        ASN1Primitive objectAsn1Primitive = object.getObject();
        return new String(((DEROctetString)objectAsn1Primitive).getOctets());
    }

    public static ASN1Integer dLTaggedObjectToASN1Integer(DLTaggedObject object) throws IOException {
        ASN1Primitive objectAsn1Primitive = object.getObject();
        byte[] objectAsByteArray = object.getEncoded();
        ASN1Integer returnValue = new ASN1Integer(Arrays.copyOfRange(objectAsByteArray,2,objectAsByteArray.length));
        return returnValue;
    }

    public static ASN1UTCTime dLTaggedObjectToASN1UTCTime(DLTaggedObject object) throws IOException {
    //FIXME
        return new ASN1UTCTime("220101010101Z");
    }

    public static ASN1GeneralizedTime dLTaggedObjectToASN1GeneralizedTime(DLTaggedObject object) throws IOException {
    //FIXME
        return new ASN1GeneralizedTime("220101010101Z");
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
