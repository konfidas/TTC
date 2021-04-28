package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.junit.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TestUnixVsGeneralized {

    @Test
    public void testEqual1() throws ParseException {

        long l = System.currentTimeMillis();

        SimpleDateFormat formatter= new SimpleDateFormat("yyyyMMddHHmmss");
        Date date = new Date(l);

        Calendar cal = Calendar.getInstance();

        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime(formatter.format(date)+"Z"));
        UnixLogTime t2 = new UnixLogTime(((l)/1000));

        assertTrue(t1.equals(t2));
    }


    @Test
    public void testDifferent1() throws ParseException {

        long l = System.currentTimeMillis();

        SimpleDateFormat formatter= new SimpleDateFormat("yyyyMMddHHmmss");
        Date date = new Date(l);

        Calendar cal = Calendar.getInstance();

        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime(formatter.format(date)+"Z"));
        UnixLogTime t2 = new UnixLogTime(((l)/1000)+1);


        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }

    @Test
    public void testDifferent2() throws ParseException {

        long l = System.currentTimeMillis();

        SimpleDateFormat formatter= new SimpleDateFormat("yyyyMMddHHmmss");
        Date date = new Date(l);

        Calendar cal = Calendar.getInstance();

        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime(formatter.format(date)+"Z"));
        UnixLogTime t2 = new UnixLogTime(((l)/1000)-1);


        assertFalse(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }
}
