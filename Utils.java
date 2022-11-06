package ua.ilyadreamix.m3amino.http.utility;

import androidx.annotation.NonNull;

import java.util.Random;
import java.lang.String;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base64;

/// DO NOT modify code like:
/// new String(Hex.encodeHex(value)) -> Hex.encodeHexString(value)
/// It will break the compatibility with older SDKs.
/// Remember that Apache Commons codec is stored in Android's /system/framework

public final class AminoRequestUtility {
    private static final String DEVICE_KEY = "02B258C63559D8804321C5D5065AF320358D366F";
    private static final String SIG_KEY = "F8E7A61AC3F725941E3AC7CAE2D688BE97F30B93";

    @NonNull
    private static String hmacSha1Hex(
        byte[] value,
        byte[] key
    ) {
        HmacUtils hmacUtils = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, key);
        byte[] hmacDigest = hmacUtils.hmac(value);
        return new String(Hex.encodeHex(hmacDigest));
    }

    private static byte[] hmacSha1Digest(
        byte[] value,
        byte[] key
    ) {
        HmacUtils hmac = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, key);
        return hmac.hmac(value);
    }

    @NonNull
    public static String generateDeviceId() throws DecoderException {
        byte[] data = new byte[20];
        byte[] key = Hex.decodeHex(DEVICE_KEY.toCharArray());

        new Random().nextBytes(data);

        String mac = hmacSha1Hex(
            ArrayUtils.addAll(
                Hex.decodeHex("42".toCharArray()),
                data
            ),
            key
        );

        return ("42" +
            new String(Hex.encodeHex(data)) +
            mac).toUpperCase();
    }

    @NonNull
    public static String generateSig(@NonNull String data) throws DecoderException {
        byte[] byteData = data.getBytes();
        byte[] key = Hex.decodeHex(SIG_KEY.toCharArray());
        byte[] mac = hmacSha1Digest(
            byteData, key
        );

        byte[] b64Bytes = Base64.encodeBase64(
            ArrayUtils.addAll(
                Hex.decodeHex("42".toCharArray()),
                mac
            )
        );

        return new String(b64Bytes);
    }
}
