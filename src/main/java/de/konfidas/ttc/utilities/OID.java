package de.konfidas.ttc.utilities;

import org.bouncycastle.util.encoders.Hex;

public enum OIDs {

    id_SE_API_transaction_log(Hex.decode(""), "0.4.0.127.0.7.3.7.1.1", "id-SE-API-transaction-log"),
    id_SE_API_SE_audit_log(Hex.decode(""), "0.4.0.127.0.7.3.7.1.1", "id-SE-API-SE-audit-log"),
    id_SE_API_system_log(Hex.decode(""), "0.4.0.127.0.7.3.7.1.1", "id-SE-API-system-log");

    byte[] encoded;
    String readable;
    String name;

    OIDs(byte[] encoded, String readable, String name){
        this.encoded = encoded;
        this.readable = readable;
        this.name = name;
    }

    public static OIDs fromBytes( byte[] encoded){

    }
}
