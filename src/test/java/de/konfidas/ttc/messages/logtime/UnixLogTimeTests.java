package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.Security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UnixLogTimeTests {
    static SecureRandom rnd;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
        rnd = new SecureRandom();
    }

    @Test
    public void testEqualUnixTimes(){
        int time =  rnd.nextInt();

        UnixLogTime t1 = new UnixLogTime(time);
        UnixLogTime t2 = new UnixLogTime(time);

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testUnixTimesOffByOne(){
        int time =  rnd.nextInt();

        UnixLogTime t1 = new UnixLogTime(time);
        UnixLogTime t2 = new UnixLogTime(time+1);

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }

}
