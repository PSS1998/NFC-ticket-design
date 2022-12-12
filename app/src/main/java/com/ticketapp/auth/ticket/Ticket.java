package com.ticketapp.auth.ticket;

import android.os.AsyncTask;
import android.util.Log;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
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

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey = TicketActivity.outer.getString(R.string.diversified_auth_key).getBytes(); // 16-byte key
    private static final byte[] hmacKey = TicketActivity.outer.getString(R.string.diversified_mac_key).getBytes();

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private static Boolean isValid = false;
    private static int remainingUses = 0;
    private static int expiryTime = 0;

    private static String infoToShow = "-"; // Use this to show messages

    private static HashMap<String, String> cardLastUsed = new HashMap<>();
    private HttpURLConnection urlConnection = null;

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
//        byte[] message = new byte[4*5];
//        res = utils.readPages(5, 5, message, 0);
//        String card_id = new String(message);
        byte[] message = new byte[4*2];
        res = utils.readPages(0, 2, message, 0);
        BigInteger cid = new BigInteger(message);
        String card_id = cid.toString();
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
        res = utils.writePages(b, 0, 6, 1);
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
            byte[] byte_diversified_key = generateDiversifiedAuthKey();
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

            resetTicketCount();

            writeInitialCounter();

            // generating new key
            writeAuthenticationKey();

        }

        int seconds_to_expiry = secondsToTicketExpiry();
        if (seconds_to_expiry == 0){
            writeInitialCounter();
            InitializeNumberOfTickets();
        }

        incNumberOfTickets();

        writeExpiryDate();

        int initial_counter = getInitialCounter();
        int int_number_of_rides = getNumberOfRides();
        int counter = getCounter();
        int number_of_tickets_left = (int_number_of_rides - (counter-initial_counter));

        boolean first_time_validation;
        if ((counter-initial_counter) == 0){
            first_time_validation = false;
        }
        else{
            first_time_validation = true;
        }

        byte[] memory = readAllMemory();

        writeMAC(memory, first_time_validation);

        if (card_is_unusable) {
            message = "This Card is Unusable".getBytes();
        }
        else{
            String message_string = "Number of tickets: "+number_of_tickets_left;
            message = message_string.getBytes();

            String card_id = getCardID();
            IOAsyncTask runner = new IOAsyncTask();
            MyTaskParams params = new MyTaskParams(card_id, "issue");
            runner.execute(params);
        }

        // Set information to show for the user
        if (res) {
            infoToShow = "Wrote: " + new String(message);
        } else {
            infoToShow = "Failed to write";
        }

        return true;
    }

    private void writeMAC(byte[] message, boolean first_time_validation) throws GeneralSecurityException {
        int page_number;
        if (first_time_validation){
            page_number = 10;
        }
        else {
            page_number = 9;
        }
        boolean res;
        byte[] byte_diversified_mac_key = generateDiversifiedMacKey();
        macAlgorithm.setKey(byte_diversified_mac_key);
        byte[] mac = new byte[4*1];
        mac = macAlgorithm.generateMac(message);
        mac = Arrays.copyOfRange(mac, 0, 4);
        res = utils.writePages(mac, 0, page_number, 1);
    }

    private byte[] readAllMemory() {
        boolean res;
        byte[] message = new byte[4*5];
        res = utils.readPages(4, 5, message, 0);
        return message;
    }

    private void writeExpiryDate() {
        boolean res;
        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime -= 1577829600; // timestamp for beginning of 2020
        unixTime += 60;
        byte[] message = ByteBuffer.allocate(4).putInt((int) unixTime).array();
        res = utils.writePages(message, 0, 7, 1);
    }

    private void incNumberOfTickets() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(6, 1, message, 0);
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
        res = utils.writePages(message, 0, 6, 1);
    }

    private int secondsToTicketExpiry() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(7, 1, message, 0);
        long expiry_date = ByteBuffer.wrap(message).getInt();
        expiryTime = Math.toIntExact(expiry_date);
        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime -= 1577829600;
        boolean expired = unixTime > expiry_date;
        if (expired == true){
            return 0;
        }
        else{
            return (int)(expiry_date - unixTime);
        }
    }

    private void writeAuthenticationKey() throws NoSuchAlgorithmException {
        boolean res;
        byte[] byte_diversified_key = generateDiversifiedAuthKey();
        res = utils.writePages(byte_diversified_key, 0, 44, 4);
    }

    private byte[] generateDiversifiedAuthKey() throws NoSuchAlgorithmException {
        boolean res;
        String master_key = new String(authenticationKey);
        return generateDiversifiedKey(master_key);
    }

    private byte[] generateDiversifiedKey(String master_key) throws NoSuchAlgorithmException {
        boolean res;
        byte[] message = new byte[4*2];
        res = utils.readPages(0, 2, message, 0);
        BigInteger cid = new BigInteger(message);
        String card_id = cid.toString();
        String diversified_key = master_key + card_id;
        MessageDigest digest = null;
        digest = MessageDigest.getInstance("SHA-256");
        byte[] byte_diversified_key = digest.digest(diversified_key.getBytes());
        byte_diversified_key = Arrays.copyOfRange(byte_diversified_key, 0, 16);
        return byte_diversified_key;
    }

    private byte[] generateDiversifiedMacKey() throws NoSuchAlgorithmException {
        boolean res;
        String master_key = new String(hmacKey);
        return generateDiversifiedKey(master_key);
    }

    private void writeInitialCounter() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(41, 1, message, 0);
        res = utils.writePages(message, 0, 8, 1);
    }

    private void resetTicketCount() {
        byte[] b = intToByteArray(0, 4);
        writeTicketCount(b);
    }

    private void writeTicketCount(byte[] value) {
        boolean res;
        res = utils.writePages(value, 0, 6, 1);
    }

    private byte[] intToByteArray(int intValue, int arraySize) {
        byte[] b;
        b = ByteBuffer.allocate(arraySize).putInt(intValue).array();
        return b;
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
        utils.readPages(41, 1, message, 0);
        byte[] byte_counter = new byte[]{message[1], message[0]};
        BigInteger bigint_counter;
        bigint_counter = new BigInteger(byte_counter);
        int counter = bigint_counter.intValue();
        if (counter >= 65527) {
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
        byte[] byte_diversified_key = generateDiversifiedAuthKey();
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
        int initial_counter = getInitialCounter();
        int counter = getCounter();
        int number_of_tickets_left = (int_number_of_rides - (counter-initial_counter));

        if ((counter-initial_counter) > 0){
            // issuing ok
            first_time_validation = false;
        }
        else if ((counter-initial_counter) == 0){
            first_time_validation = true;
        }
        else{
            // error
            ticket_validation_was_not_success = true;
        }

        int seconds_to_expiry;
        if (first_time_validation){
            seconds_to_expiry = 60;
        }
        else {
            seconds_to_expiry = secondsToTicketExpiry();
            if (seconds_to_expiry == 0) {
                // error
                System.out.println("ticket was expired");
                ticket_validation_was_not_success = true;
            }
        }

        boolean invalid_expiry_date = isTicketExpiryMoreThanLimit();
        if (invalid_expiry_date){
            System.out.println("invalid expiry");
            ticket_validation_was_not_success = true;
        }

        byte[] mac = getMAC(first_time_validation);

        byte[] memory = readAllMemory();

        byte[] byte_diversified_mac_key = generateDiversifiedMacKey();
        macAlgorithm.setKey(byte_diversified_mac_key);
        byte[] new_mac = macAlgorithm.generateMac(memory);
        new_mac = Arrays.copyOfRange(new_mac, 0, 4);
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
                writeMAC(memory, true);
            }
        }

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

        if (cardLastUsed.containsKey(card_id)) {
            long last_used = Long.parseLong(cardLastUsed.get(card_id));
            long unixTime = System.currentTimeMillis() / 1000L;
            if ((unixTime - 3) < last_used) {
                System.out.println("double tap by mistake");
                ticket_validation_was_not_success = true;
            }
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
            String message_string = "Ticket validation was a success. Rides left: "+(number_of_tickets_left-1)+", Time left: "+seconds_to_expiry;
            message = message_string.getBytes();

            long unixTime = System.currentTimeMillis() / 1000L;
            cardLastUsed.put(card_id, String.valueOf(unixTime));

            IOAsyncTask runner = new IOAsyncTask();
            MyTaskParams params = new MyTaskParams(card_id, "validation");
            runner.execute(params);
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
        int int_limit_number_of_rides = 100;
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
        res = utils.readPages(8, 1, message, 0);
        byte[] byte_initial_counter = new byte[]{message[1], message[0]};
        BigInteger bigint_initial_counter;
        bigint_initial_counter = new BigInteger(byte_initial_counter);
        int initial_counter = bigint_initial_counter.intValue();
        return initial_counter;
    }

    private void updateExpiryDate() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(7, 1, message, 0);
        long expiry_date = ByteBuffer.wrap(message).getInt();
        long unixTime = System.currentTimeMillis() / 1000L;
        unixTime -= 1577829600;
        expiry_date = expiry_date + (60 - (expiry_date - unixTime));
        message = ByteBuffer.allocate(4).putInt((int) expiry_date).array();
        res = utils.writePages(message, 0, 7, 1);
    }

    private byte[] getMAC(boolean first_time_validation) {
        int page_number;
        if (first_time_validation){
            page_number = 9;
        }
        else {
            page_number = 10;
        }
        boolean res;
        byte[] message = new byte[4*1];
        res = utils.readPages(page_number, 1, message, 0);
        byte[] mac = Arrays.copyOf(message, message.length);
        return mac;
    }

    private boolean isTicketExpiryMoreThanLimit() {
        boolean res;
        int limit_expiry_date = 1576800000; // 50 years
        byte[] message = new byte[4];
        res = utils.readPages(7, 1, message, 0);
        long expiry_date = ByteBuffer.wrap(message).getInt();
        boolean invalid_expiry_date = expiry_date > limit_expiry_date;
        return invalid_expiry_date;
    }

    private int getNumberOfRides() {
        boolean res;
        byte[] message = new byte[4];
        res = utils.readPages(6, 1, message, 0);
        BigInteger bigint_number_of_rides = new BigInteger(message);
        int int_number_of_rides = bigint_number_of_rides.intValue();
        return int_number_of_rides;
    }

    private String getCardID() {
        boolean res;
        byte[] message = new byte[4*2];
        res = utils.readPages(0, 2, message, 0);
        BigInteger cid = new BigInteger(message);
        String card_id = cid.toString();
        return card_id;
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

    private void sendLogToServer(String card_id, String type) {
        try {
            URL url = new URL("http://3.82.215.225:5000/ticketing-log");

            urlConnection = (HttpURLConnection) url.openConnection();

            urlConnection.setReadTimeout(10000);
            urlConnection.setConnectTimeout(15000);
            urlConnection.setRequestMethod("POST");
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);

            long unixTime = System.currentTimeMillis() / 1000L;
            String string_timestamp = String.valueOf(unixTime);
            string_timestamp = String.format("%10s", string_timestamp).replace(" ", "0");

            HashMap<String, String> params = new HashMap<String, String>();
            params.put("ID", card_id);
            params.put("type", type);
            params.put("time", string_timestamp);

            StringBuilder result = new StringBuilder();
            boolean first = true;
            for(Map.Entry<String, String> entry : params.entrySet()){
                if (first)
                    first = false;
                else
                    result.append("&");
                result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
                result.append("=");
                result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            }

            OutputStream os = new BufferedOutputStream(urlConnection.getOutputStream());
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
            writer.write(result.toString());
            writer.flush();

            int code = urlConnection.getResponseCode();

            BufferedReader rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String line;
            while ((line = rd.readLine()) != null) {
                Log.i("data", line);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }

    private static class MyTaskParams {
        String id;
        String type;

        MyTaskParams(String id, String type) {
            this.id = id;
            this.type = type;
        }
    }

    class IOAsyncTask extends AsyncTask<MyTaskParams, Void, String> {
        @Override
        protected String doInBackground(MyTaskParams... params) {
            sendLogToServer(params[0].id, params[0].type);
            return "done";
        }

        @Override
        protected void onPostExecute(String response) {
            Log.d("networking", response);
        }
    }
}