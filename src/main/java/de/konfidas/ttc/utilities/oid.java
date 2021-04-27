package de.konfidas.ttc.utilities;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public enum oid {

    id_SE_API_transaction_log( Hex.decode("06 09 04 00 7F 00 07 03 07 01 01".replace("\\\\s+","")), "0.4.0.127.0.7.3.7.1.1", "id-SE-API-transaction-log"),
    id_SE_API_system_log     ( Hex.decode("06 09 04 00 7F 00 07 03 07 01 02".replace("\\\\s+","")), "0.4.0.127.0.7.3.7.1.2", "id-SE-API-system-log"),
    id_SE_API_SE_audit_log   ( Hex.decode("06 09 04 00 7F 00 07 03 07 01 03".replace("\\\\s+","")), "0.4.0.127.0.7.3.7.1.3", "id-SE-API-SE-audit-log");

    final byte[] encoded;
    final String readable;
    final String name;

    oid(byte[] encoded, String readable, String name){
        this.encoded = encoded;
        this.readable = readable;
        this.name = name;
    }

    public byte[] getEncoded(){
        return encoded;
    }

    public String getName(){
        return name;
    }

    public String getReadable() {
        return readable;
    }

    public static oid fromBytes(byte[] encoded) throws UnknownOidException {
        for(de.konfidas.ttc.utilities.oid oid : oid.values()){
            if (Arrays.equals(oid.getEncoded(), encoded)){
                return oid;
            }
        }
        throw new UnknownOidException("unknown Oid:"+Hex.toHexString(encoded));
    }

    public static class UnknownOidException extends BadFormatForLogMessageException {
        public UnknownOidException(String message) {
            super(message);
        }
    }
}