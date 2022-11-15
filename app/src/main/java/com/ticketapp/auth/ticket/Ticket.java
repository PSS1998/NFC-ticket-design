package com.ticketapp.auth.ticket;

import android.util.Log;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.sql.Timestamp;
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

        // Example of writing:
        byte[] message = "Tckt".getBytes();
        res = utils.writePages(message, 0, 4, 1);

        message = "0001".getBytes();
        res = utils.writePages(message, 0, 5, 1);

        String uuid = UUID.randomUUID().toString().substring(0,16);
        message = uuid.getBytes();
        res = utils.writePages(message, 0, 6, 4);

        message = "0000".getBytes();
        res = utils.writePages(message, 0, 10, 1);

        message = new byte[4];
        res = utils.readPages(10, 1, message, 0);
        String number_of_rides = new String(message);
        int int_number_of_rides = Integer.parseInt(number_of_rides, 2);
        int_number_of_rides += 5;

        number_of_rides = Integer.toBinaryString(int_number_of_rides);
        number_of_rides = String.format("%4s", number_of_rides).replace(" ", "0");
        message = number_of_rides.getBytes();
        res = utils.writePages(message, 0, 10, 1);

        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime += 60;
        String string_timestamp = String.valueOf(unixTime);
        System.out.println(string_timestamp);
        string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
        message = string_timestamp.getBytes();
        res = utils.writePages(message, 0, 11, 3);

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

        // Example of reading:
        byte[] message = new byte[4];
        res = utils.readPages(4, 1, message, 0);
        String app_name = new String(message);

        message = new byte[4];
        res = utils.readPages(5, 1, message, 0);
        String app_version = new String(message);

        message = new byte[16];
        res = utils.readPages(6, 4, message, 0);
        String card_id = new String(message);


        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}