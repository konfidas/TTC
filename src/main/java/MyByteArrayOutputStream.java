import java.io.ByteArrayOutputStream;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

/**
 * Diese Klasse überschreibt die toString Methode des ByteArrayOutputStream. Dies verbessert die Anzeige in der IDE
 */
public class MyByteArrayOutputStream extends ByteArrayOutputStream{

    public String toString() {
        return encodeHexString(this.toByteArray());
    }

}
