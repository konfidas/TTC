package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;

import java.text.ParseException;
import java.util.Calendar;

public class GeneralizedLogTime extends LogTime {
    ASN1GeneralizedTime element;
    long time;

    // FIXME: I am currently unsure, where to take this offset into account!
    final static long offset =  Calendar.getInstance().get(Calendar.DST_OFFSET) + Calendar.getInstance().get(Calendar.ZONE_OFFSET);


    public GeneralizedLogTime(ASN1GeneralizedTime element) throws ParseException {
        this.element = element;
        this.time = element.getDate().getTime() - offset;
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
