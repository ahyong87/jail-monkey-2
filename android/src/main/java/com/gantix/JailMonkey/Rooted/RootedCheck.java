package com.gantix.JailMonkey.Rooted;

import android.content.Context;

import com.scottyab.rootbeer.RootBeer;
import android.os.Build;

public class RootedCheck {

    private static final String ONEPLUS = "oneplus";
    private static final String MOTO = "moto";

    /**
     * Checks if the device is rooted.
     *
     * @return <code>true</code> if the device is rooted, <code>false</code> otherwise.
     */
    public static String isNotOriginal(Context context) {
        CheckApiVersion check;

        if (android.os.Build.VERSION.SDK_INT >= 23) {
            check = new GreaterThan23();
        } else {
            check = new LessThan23();
        }
        if (check.checkRooted() || rootBeerCheck(context)) {
            return "Unsafe! This phone is Jail Broken";
        }

        return "This is safe to use!";
    }

    private static boolean rootBeerCheck(Context context) {
        RootBeer rootBeer = new RootBeer(context);
        Boolean rv;
        if(Build.BRAND.contains(ONEPLUS) || Build.BRAND.contains(MOTO)) {
            rv = rootBeer.isRootedWithoutBusyBoxCheck();
        } else {
            rv = rootBeer.isRooted();
        }
        return rv;
    }
}
