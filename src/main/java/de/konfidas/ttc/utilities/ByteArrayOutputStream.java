package de.konfidas.ttc.utilities;


import static org.apache.commons.codec.binary.Hex.encodeHexString;

/**
 * Diese Klasse überschreibt die toString Methode des ByteArrayOutputStream. Dies verbessert die Anzeige in der IDE
 */
public class ByteArrayOutputStream extends java.io.ByteArrayOutputStream {

    public String toString() {
        return encodeHexString(this.toByteArray());
    }

}
