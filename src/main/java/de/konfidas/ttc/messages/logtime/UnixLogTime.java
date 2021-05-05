package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1Integer;

public class UnixLogTime extends LogTime {
    final long time;

    public UnixLogTime(long time) {
        this.time = time;
    }

    public UnixLogTime(ASN1Integer time) {
        this.time = time.getValue().longValue();
    }

    @Override
    public String toString(){
        return Long.valueOf(time).toString();
    }

    @Override
    public long getTime() {
        return time*1000;
    }

    @Override
    public Type getType() {
        return Type.UNIX;
    }
    public long getValue(){
        return time;
    }
}
