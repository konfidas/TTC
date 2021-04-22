package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;

import java.text.ParseException;

public class GeneralizedLogTime extends LogTime {
    ASN1GeneralizedTime element;
    long time;

    public GeneralizedLogTime(ASN1GeneralizedTime element) throws ParseException {
        this.element = element;
        this.time = element.getDate().getTime();
    }

    @Override
    public String toString(){
        return element.getTimeString();
    }


    @Override
    public long getTime() {
        return time;
    }

    @Override
    public Type getType() {
        return Type.GENERALIZED;
    }
}
