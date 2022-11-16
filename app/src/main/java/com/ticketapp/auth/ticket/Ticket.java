package com.ticketapp.auth.ticket;

import android.util.Log;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.UUID;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You will
 * need to change the keys, design and implement functions to issue and validate tickets. Keep your
 * code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;

    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        byte[] message = "Tckt".getBytes();
        res = utils.writePages(message, 0, 4, 1);

        message = "0001".getBytes();
        res = utils.writePages(message, 0, 5, 1);

        String uuid = UUID.randomUUID().toString().substring(0,16);
        message = uuid.getBytes();
        res = utils.writePages(message, 0, 6, 4);

        int a = 0;
        byte[] b = new byte[4];
        b = ByteBuffer.allocate(4).putInt(a).array();
        res = utils.writePages(b, 0, 10, 1);

        message = new byte[4];
        res = utils.readPages(10, 1, message, 0);
        BigInteger bigint_number_of_rides = new BigInteger(message);
        int int_number_of_rides = bigint_number_of_rides.intValue();
        int_number_of_rides += 5;

        message = ByteBuffer.allocate(4).putInt(int_number_of_rides).array();
        res = utils.writePages(message, 0, 10, 1);

        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime += 60;
        String string_timestamp = String.valueOf(unixTime);
        string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
        message = string_timestamp.getBytes();
        res = utils.writePages(message, 0, 11, 3);

        message = ByteBuffer.allocate(4).putInt(100).array();
        res = utils.writePages(message, 0, 14, 1);

        unixTime = System.currentTimeMillis() / 1000L;
        unixTime += 31104000;
        string_timestamp = String.valueOf(unixTime);
        string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
        message = string_timestamp.getBytes();
        res = utils.writePages(message, 0, 15, 3);

        message = new byte[4];
        res = utils.readPages(3, 1, message, 0);

        res = utils.writePages(message, 0, 18, 1);

        // print byte in binary format
//        BigInteger one;
//        one = new BigInteger(message);
//        String strResult = one.toString(2);
//        System.out.println("ByteArray to Binary = "+strResult);

        message = new byte[4*15];
        res = utils.readPages(4, 15, message, 0);

        byte[] mac = new byte[4*5];
        mac = macAlgorithm.generateMac(message);
        res = utils.writePages(mac, 0, 19, 5);

        // reset counter

        // inc otp

        // Set information to show for the user
        if (res) {
            infoToShow = "Wrote: " + new String(message);
        } else {
            infoToShow = "Failed to write";
        }

        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        byte[] message = new byte[4];
        res = utils.readPages(4, 1, message, 0);
        String app_name = new String(message);

        message = new byte[4];
        res = utils.readPages(5, 1, message, 0);
        String app_version = new String(message);

        message = new byte[16];
        res = utils.readPages(6, 4, message, 0);
        String card_id = new String(message);

        message = new byte[4];
        res = utils.readPages(10, 1, message, 0);
        BigInteger bigint_number_of_rides = new BigInteger(message);
        int int_number_of_rides = bigint_number_of_rides.intValue();

        message = new byte[12];
        res = utils.readPages(11, 3, message, 0);
        String string_message = new String(message);
        long expiry_date = Long.parseLong(string_message.substring(2,12));
        long unixTime = System.currentTimeMillis() / 1000L;
        boolean expired = unixTime > expiry_date;

        message = new byte[4];
        res = utils.readPages(14, 1, message, 0);
        BigInteger bigint_limit_number_of_rides = new BigInteger(message);
        int int_limit_number_of_rides = bigint_limit_number_of_rides.intValue();
        boolean invalid_number_of_tickets = int_number_of_rides > int_limit_number_of_rides;

        message = new byte[12];
        res = utils.readPages(15, 3, message, 0);
        string_message = new String(message);
        long limit_expiry_date = Long.parseLong(string_message.substring(2,12));
        boolean invalid_expiry_date = expiry_date > limit_expiry_date;

        message = new byte[4];
        res = utils.readPages(3, 1, message, 0);
        BigInteger bigint_otp = new BigInteger(message);
        long otp = bigint_otp.longValue();

        message = new byte[4];
        res = utils.readPages(18, 1, message, 0);
        BigInteger bigint_initial_otp = new BigInteger(message);
        long initial_otp = bigint_initial_otp.longValue();
        if ((otp-initial_otp) == 2){
            // otp ok
        }
        else if ((otp-initial_otp) == 1){
            unixTime = System.currentTimeMillis() / 1000L;
            String string_timestamp = String.valueOf(unixTime);
            string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
            message = string_timestamp.getBytes();
            res = utils.writePages(message, 0, 24, 3);
            // inc otp
        }
        else{
            // error
        }

        message = new byte[4*5];
        res = utils.readPages(19, 5, message, 0);
        byte[] mac = message;

        message = new byte[4*15];
        res = utils.readPages(4, 15, message, 0);
        byte[] new_mac = new byte[4*5];
        new_mac = macAlgorithm.generateMac(message);
        if (!Arrays.equals(mac, new_mac)){
            // error
        }
        else{
        }

        // inc counter

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}