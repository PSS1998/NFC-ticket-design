package com.ticketapp.auth.ticket;

import android.util.Log;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
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
    private static final byte[] authenticationKey = TicketActivity.outer.getString(R.string.diversified_auth_key).getBytes(); // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private static Boolean isValid = false;
    private static int remainingUses = 0;
    private static int expiryTime = 0;

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

    public static void resetCardForDebug() {
        boolean res;
        String master_key = new String(authenticationKey);
        byte[] message = new byte[4*5];
        res = utils.readPages(5, 5, message, 0);
        String card_id = new String(message);
        String diversified_key = master_key + card_id;
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch(Exception e){

        }
        byte[] byte_diversified_key = digest.digest(diversified_key.getBytes());
        byte_diversified_key = Arrays.copyOfRange(byte_diversified_key, 0, 16);
        res = utils.authenticate(byte_diversified_key);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return;
        }
        message = "Tttt".getBytes();
        res = utils.writePages(message, 0, 4, 1);
        res = utils.writePages(defaultAuthenticationKey, 0, 44, 4);
        int a = 0;
        byte[] b = new byte[4];
        b = ByteBuffer.allocate(4).putInt(a).array();
        res = utils.writePages(b, 0, 10, 1);
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        byte[] message;

//        resetCardForDebug();

        boolean is_card_formated = false;
        boolean card_is_unusable = false;
        try {
            message = new byte[4];
            res = utils.readPages(4, 1, message, 0);
            String app_name = new String(message);
            if (res) {
                if (app_name.equals("Tckt")) {
                    is_card_formated = true;
                    card_is_unusable = isCardUnUsable();
                }
                else {
                    // Authenticate
                    res = utils.authenticate(defaultAuthenticationKey);
                    if (!res) {
                        Utilities.log("Authentication failed in issue()", true);
                        infoToShow = "Authentication failed";
                        return false;
                    }
                    is_card_formated = false;
                    card_is_unusable = isCardUnUsable();
                }
            }
            else {
                // Authenticate
                res = utils.authenticate(defaultAuthenticationKey);
                if (!res) {
                    Utilities.log("Authentication failed in issue()", true);
                    infoToShow = "Authentication failed";
                    return false;
                }
                is_card_formated = false;
                card_is_unusable = isCardUnUsable();
            }
        }
        catch(Exception e) {
            // Authenticate
            res = utils.authenticate(defaultAuthenticationKey);
            if (!res) {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }
            is_card_formated = false;
            card_is_unusable = isCardUnUsable();
        }

        if(is_card_formated) {
            // Authenticate using our key
            byte[] byte_diversified_key = GenerateDiversifiedKey();
            res = utils.authenticate(byte_diversified_key);
            if (!res) {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }
        }

        if (!is_card_formated) {

            writeAUTH1();

            writeAUTH0();

            writeApplicationName();

            writeApplicationVersion();

            writeCardID();

            resetTicketCount();

            writeInitialCounter();

            // generating new key
            writeAuthenticationKey();

        }

        boolean expired = isTicketExpired();
        if (expired){
            writeInitialCounter();
            InitializeNumberOfTickets();
        }

        incNumberOfTickets();

        writeExpiryDate();

        writeLimitOfNumberOfTickets();

        writeLimitOfExpiryDate();

        byte[] byte_otp = writeInitialOTP();

        byte[] memory = readAllMemory();

        writeMAC(memory);

        res = incOTP(card_is_unusable, byte_otp);

        if (card_is_unusable) {
            message = "This Card is Unusable".getBytes();
        }
        else{
            message = "Card issued successfully".getBytes();
        }

        // Set information to show for the user
        if (res) {
            infoToShow = "Wrote: " + new String(message);
        } else {
            infoToShow = "Failed to write";
        }

        return true;
    }

    private boolean incOTP(boolean card_is_unusable, byte[] byte_otp) {
        boolean res;
        byte[] message = new byte[4];
        BigInteger bigint_otp;
        bigint_otp = new BigInteger(byte_otp);
        if (!card_is_unusable) {
            bigint_otp = bigint_otp.add(BigInteger.valueOf(1));
        }
        message = ByteBuffer.allocate(4).put(bigint_otp.toByteArray()).array();
        res = utils.writePages(message, 0, 3, 1);
        return res;
    }

    private void writeMAC(byte[] message) {
        boolean res;
        byte[] mac = new byte[4*5];
        mac = macAlgorithm.generateMac(message);
        res = utils.writePages(mac, 0, 20, 5);
    }

    private byte[] readAllMemory() {
        boolean res;
        byte[] message = new byte[4*16];
        res = utils.readPages(4, 16, message, 0);
        return message;
    }

    private byte[] writeInitialOTP() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(3, 1, message, 0);
        byte[] byte_otp = Arrays.copyOf(message, message.length);
        res = utils.writePages(message, 0, 18, 1);
        return byte_otp;
    }

    private void writeLimitOfExpiryDate() {
        boolean res;
        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime += 31104000;
        String string_timestamp = String.valueOf(unixTime);
        string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
        byte[] message = string_timestamp.getBytes();
        res = utils.writePages(message, 0, 15, 3);
    }

    private void writeLimitOfNumberOfTickets() {
        boolean res;
        byte[] message = intToByteArray(100, 4);
        res = utils.writePages(message, 0, 14, 1);
    }

    private void writeExpiryDate() {
        boolean res;
        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime += 60;
        String string_timestamp = String.valueOf(unixTime);
        string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
        byte[] message = string_timestamp.getBytes();
        res = utils.writePages(message, 0, 11, 3);
    }

    private void incNumberOfTickets() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(10, 1, message, 0);
        BigInteger bigint_number_of_rides = new BigInteger(message);
        int int_number_of_rides = bigint_number_of_rides.intValue();
        int_number_of_rides += 5;

        message = intToByteArray(int_number_of_rides, 4);
        writeNumberOfTickets(message);
    }

    private void InitializeNumberOfTickets() {
        byte[] message = intToByteArray(0, 4);
        writeNumberOfTickets(message);
    }

    private void writeNumberOfTickets(byte[] message) {
        boolean res;
        res = utils.writePages(message, 0, 10, 1);
    }

    private boolean isTicketExpired() {
        boolean res;
        byte[] message = new byte[12];
        res = utils.readPages(11, 3, message, 0);
        String string_message = new String(message);
        long expiry_date = Long.parseLong(string_message.substring(2,12));
        expiryTime = Math.toIntExact(expiry_date);
        long unixTime = System.currentTimeMillis() / 1000L;
        boolean expired = unixTime > expiry_date;
        return expired;
    }

    private void writeAuthenticationKey() throws NoSuchAlgorithmException {
        boolean res;
        byte[] byte_diversified_key = GenerateDiversifiedKey();
        res = utils.writePages(byte_diversified_key, 0, 44, 4);
    }

    private byte[] GenerateDiversifiedKey() throws NoSuchAlgorithmException {
        boolean res;
        String master_key = new String(authenticationKey);
        byte[] message = new byte[4*5];
        res = utils.readPages(5, 5, message, 0);
        String card_id = new String(message);
        String diversified_key = master_key + card_id;
        MessageDigest digest = null;
        digest = MessageDigest.getInstance("SHA-256");
        byte[] byte_diversified_key = digest.digest(diversified_key.getBytes());
        byte_diversified_key = Arrays.copyOfRange(byte_diversified_key, 0, 16);
        return byte_diversified_key;
    }

    private void writeInitialCounter() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(41, 1, message, 0);
        res = utils.writePages(message, 0, 19, 1);
    }

    private void resetTicketCount() {
        byte[] b = intToByteArray(0, 4);
        writeTicketCount(b);
    }

    private void writeTicketCount(byte[] value) {
        boolean res;
        res = utils.writePages(value, 0, 10, 1);
    }

    private byte[] intToByteArray(int intValue, int arraySize) {
        byte[] b;
        b = ByteBuffer.allocate(arraySize).putInt(intValue).array();
        return b;
    }

    private void writeCardID() {
        boolean res;
        String uuid = UUID.randomUUID().toString().substring(0, 16);
        byte[] message = uuid.getBytes();
        res = utils.writePages(message, 0, 6, 4);
    }

    private void writeApplicationVersion() {
        boolean res;
        byte[] message = "0001".getBytes();
        res = utils.writePages(message, 0, 5, 1);
    }

    private void writeApplicationName() {
        boolean res;
        byte[] message = "Tckt".getBytes();
        res = utils.writePages(message, 0, 4, 1);
    }

    private void writeAUTH0() {
        boolean res;
        byte[] byte_AUTH0 = new byte[4];
        byte_AUTH0 = intToByteArray(10, 4);
        byte[] message = new byte[]{byte_AUTH0[3], byte_AUTH0[0], byte_AUTH0[1], byte_AUTH0[2]};
        res = utils.writePages(message, 0, 42, 1);
    }

    private void writeAUTH1() {
        boolean res;
        byte[] byte_AUTH1 = new byte[4];
        byte_AUTH1 = intToByteArray(0, 4);
        byte[] message = new byte[]{byte_AUTH1[3], byte_AUTH1[0], byte_AUTH1[1], byte_AUTH1[2]};
        res = utils.writePages(message, 0, 43, 1);
    }

    private boolean isCardUnUsable() {
        byte[] message = new byte[4];
        utils.readPages(3, 1, message, 0);
        BigInteger bigint_otp = new BigInteger(message);
        String strResult = bigint_otp.toString(2);
        int otp = strResult.length() - strResult.replace("1", "").length();
        if (otp >= 30) {
            return true;
        }
        return false;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        byte[] message;

        boolean ticket_validation_was_not_success = false;
        boolean first_time_validation = false;

        // Authenticate
        byte[] byte_diversified_key = GenerateDiversifiedKey();
        res = utils.authenticate(byte_diversified_key);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        String app_name = getAppName();
        if (!app_name.equals("Tckt")){
            // error
            System.out.println("app name was wrong");
            ticket_validation_was_not_success = true;
        }

        String app_version = getAppVersion();
        if (!app_version.equals("0001")){
            // error
            System.out.println("app version was wrong");
            ticket_validation_was_not_success = true;
        }

        String card_id = getCardID();

        int int_number_of_rides = getNumberOfRides();

        boolean expired = isTicketExpired();
        if (expired){
            // error
            System.out.println("ticket was expired");
            ticket_validation_was_not_success = true;
        }

        boolean invalid_expiry_date = isTicketExpiryMoreThanLimit();
        if (invalid_expiry_date){
            System.out.println("invalid expiry");
            ticket_validation_was_not_success = true;
        }

        int otp = getOTP();

        int initial_otp = getInitialOTP();

        if ((otp-initial_otp) == 2){
            // otp ok
            first_time_validation = false;
        }
        else if ((otp-initial_otp) == 1){
            first_time_validation = true;
        }
        else{
            // error
            System.out.println("wrong otp");
//            ticket_validation_was_not_success = true;
        }

        byte[] mac = getMAC();

        byte[] memory = readAllMemory();

        byte[] new_mac = macAlgorithm.generateMac(memory);
        if (!Arrays.equals(mac, new_mac)){
            // error
            System.out.println("wrong mac");
            ticket_validation_was_not_success = true;
        }
        else{
            // mac is correct
            if (first_time_validation) {
                updateExpiryDate();

                // calculate new mac and write it to memory
                memory = readAllMemory();
                writeMAC(memory);

                byte[] byte_otp = new byte[4];
                res = utils.readPages(3, 1, byte_otp, 0);
                res = incOTP(false, byte_otp);
            }
        }

        int initial_counter = getInitialCounter();

        int counter = getCounter();
        int number_of_tickets_left = (int_number_of_rides - (counter-initial_counter));
        if (number_of_tickets_left <= 0){
            remainingUses = number_of_tickets_left;
            System.out.println("no ticket left");
            ticket_validation_was_not_success = true;
        }

        int int_limit_number_of_rides = getLimitOfNumberOfTickets();
        boolean invalid_number_of_tickets = (int_number_of_rides - (counter-initial_counter)) > int_limit_number_of_rides;
        if (invalid_number_of_tickets){
            System.out.println("more ticket than limit");
            ticket_validation_was_not_success = true;
        }

        if (!ticket_validation_was_not_success) {
            res = incCounter();
        }

        if (ticket_validation_was_not_success){
            isValid = false;
            message = "Ticket validation was not a success".getBytes();
        }
        else {
            isValid = true;
            message = "Ticket validation was a success".getBytes();
        }

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }

    private boolean incCounter() {
        boolean res;
        byte[] byte_counter_left = new byte[4];
        byte[] byte_counter_right = new byte[4];
        byte_counter_left = intToByteArray(1, 4);
        byte_counter_right = intToByteArray(0, 4);
        byte[] message = new byte[]{byte_counter_left[3], byte_counter_left[2], byte_counter_right[3], byte_counter_right[2]};
        res = utils.writePages(message, 0, 41, 1);
        return res;
    }

    private int getLimitOfNumberOfTickets() {
        byte[] message = new byte[4];
        boolean res = utils.readPages(14, 1, message, 0);
        BigInteger bigint_limit_number_of_rides = new BigInteger(message);
        int int_limit_number_of_rides = bigint_limit_number_of_rides.intValue();
        return int_limit_number_of_rides;
    }

    private int getCounter() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(41, 1, message, 0);
        byte[] byte_counter = new byte[]{message[1], message[0]};
        BigInteger bigint_counter;
        bigint_counter = new BigInteger(byte_counter);
        int counter = bigint_counter.intValue();
        return counter;
    }

    private int getInitialCounter() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(19, 1, message, 0);
        byte[] byte_initial_counter = new byte[]{message[1], message[0]};
        BigInteger bigint_initial_counter;
        bigint_initial_counter = new BigInteger(byte_initial_counter);
        int initial_counter = bigint_initial_counter.intValue();
        return initial_counter;
    }

    private void updateExpiryDate() {
        boolean res;
        byte[] message = new byte[12];
        res = utils.readPages(11, 3, message, 0);
        String string_message = new String(message);
        long expiry_date = Long.parseLong(string_message.substring(2, 12));
        long unixTime = System.currentTimeMillis() / 1000L;
        expiry_date = expiry_date + (60 - (expiry_date - unixTime));
        String string_timestamp = String.valueOf(expiry_date);
        string_timestamp = String.format("%12s", string_timestamp).replace(" ", "0");
        message = string_timestamp.getBytes();
        res = utils.writePages(message, 0, 11, 3);
    }

    private byte[] getMAC() {
        boolean res;
        byte[] message = new byte[4*5];
        res = utils.readPages(20, 5, message, 0);
        byte[] mac = Arrays.copyOf(message, message.length);
        return mac;
    }

    private int getInitialOTP() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(18, 1, message, 0);
        int initial_otp = calculateValueOfOTP(message);
        return initial_otp;
    }

    private int getOTP() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(3, 1, message, 0);
        int otp = calculateValueOfOTP(message);
        return otp;
    }

    private int calculateValueOfOTP(byte[] message) {
        BigInteger bigint_otp2 = new BigInteger(message);
        String strResult2 = bigint_otp2.toString(2);
        int otp = strResult2.length() - strResult2.replace("1", "").length();
        return otp;
    }

    private boolean isTicketExpiryMoreThanLimit() {
        boolean res;
        byte[] message = new byte[12];
        res = utils.readPages(11, 3, message, 0);
        String string_message = new String(message);
        long expiry_date = Long.parseLong(string_message.substring(2,12));
        res = utils.readPages(15, 3, message, 0);
        string_message = new String(message);
        long limit_expiry_date = Long.parseLong(string_message.substring(2,12));
        boolean invalid_expiry_date = expiry_date > limit_expiry_date;
        return invalid_expiry_date;
    }

    private int getNumberOfRides() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(10, 1, message, 0);
        BigInteger bigint_number_of_rides = new BigInteger(message);
        int int_number_of_rides = bigint_number_of_rides.intValue();
        return int_number_of_rides;
    }

    private String getCardID() {
        boolean res;
        byte[] message = new byte[16];
        res = utils.readPages(6, 4, message, 0);
        return new String(message);
    }

    private String getAppVersion() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(5, 1, message, 0);
        String app_version = new String(message);
        return app_version;
    }

    private String getAppName() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(4, 1, message, 0);
        String app_name = new String(message);
        return app_name;
    }
}