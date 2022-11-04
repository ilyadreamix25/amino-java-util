package ua.ilyadreamix.m3amino.http.utility;

import java.util.Random;
import java.util.HexFormat;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base64;

public final class Utils {
    private final String KEY = "02B258C63559D8804321C5D5065AF320358D366F";
    private final String SIG_KEY = "F8E7A61AC3F725941E3AC7CAE2D688BE97F30B93";

    private byte[] hexToBytes(String str) {
        return HexFormat.of().parseHex(str);
    }

    public String hmacSha1Hex(
        byte[] value,
        byte[] key
    ) {          
        HmacUtils hmac = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, key);
        return hmac.hmacHex(value);
    }

    public byte[] hmacSha1Digest(
        byte[] value,
        byte[] key
    ) {
        HmacUtils hmac = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, key);
        return hmac.hmac(value);
    }

    public String generateDeviceId() {
        byte[] data;
        byte[] key;

        data = new byte[20];
        key = this.hexToBytes(this.KEY);
        new Random().nextBytes(data);

        String mac = this.hmacSha1Hex(
            ArrayUtils.addAll(
                this.hexToBytes("42"),
                data
            ),
            key
        );

        return ("42" +
            Hex.encodeHexString(data) +
            mac).toUpperCase();
    }

    public String generateSig(String data) {
        byte[] byteData = data.getBytes();
        byte[] key = this.hexToBytes(this.SIG_KEY);
        byte[] mac = this.hmacSha1Digest(
            byteData, key
        );

        byte[] b64Bytes = Base64.encodeBase64(
            ArrayUtils.addAll(
                this.hexToBytes("42"),
                mac
            )
        );
        return new String(b64Bytes);
    }
}
