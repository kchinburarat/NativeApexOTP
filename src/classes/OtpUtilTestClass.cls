@isTest
public class OtpUtilTestClass {

    static testMethod void validate_MAX() {
        final string Base16 = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
        final string Base32 = '77777777777777777777777777777777';
        System.assertEquals(Base32, otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16, otpUtil.keyB32toB16(Base32));
    }

    static testMethod void validate_MIN() {
        final string Base16 = '0000000000000000000000000000000000000000';
        final string Base32 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        System.assertEquals(Base32, otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16, otpUtil.keyB32toB16(Base32));
    }

    static testMethod void validate_Pattern_10() {
        final string Base16 = 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD';
        final string Base32 = '3XO53XO53XO53XO53XO53XO53XO53XO5';
        System.assertEquals(Base32, otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16, otpUtil.keyB32toB16(Base32));
    }

    static testMethod void validate_Pattern_01() {
        final string Base16 = '5555555555555555555555555555555555555555';
        final string Base32 = 'KVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKV';
        System.assertEquals(Base32, otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16, otpUtil.keyB32toB16(Base32));
    }

    static testMethod void validate_Random() {
        final string Base16 = '02A6FFC209CB208673AEFCBB021FE45398D68CA9';
        final string Base32 = 'AKTP7QQJZMQIM45O7S5QEH7EKOMNNDFJ';
        System.assertEquals(Base32, otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16, otpUtil.keyB32toB16(Base32));
    }


    static testMethod void validate_Dynamic() {
        String Base16 = '';
        String Base32 = '';
        for (Integer i = 0; i < 10; i++) {
            Base16 = otpUtil.generateBase16Key();
            Base32 = otpUtil.keyB16toB32(Base16);
            System.assertEquals(Base16.toUpperCase(), otpUtil.keyB32toB16(Base32));
            Base32 = otpUtil.generateBase32Key();
            Base16 = otpUtil.keyB32toB16(Base32);
            System.assertEquals(Base32, otpUtil.keyB16toB32(Base16));
        }
    }

    static testMethod void Validate_RFC4226() {
        final String RFC_HEX_KEY = '3132333435363738393031323334353637383930';
        System.assert(otpUtil.validateHOTP('755224', otpUtil.keyB16toB32(RFC_HEX_KEY), 0L, 0));
        System.assert(otpUtil.validateHOTP('287082', otpUtil.keyB16toB32(RFC_HEX_KEY), 1L, 0));
        System.assert(otpUtil.validateHOTP('359152', otpUtil.keyB16toB32(RFC_HEX_KEY), 2L, 0));
        System.assert(otpUtil.validateHOTP('969429', otpUtil.keyB16toB32(RFC_HEX_KEY), 3L, 0));
        System.assert(otpUtil.validateHOTP('338314', otpUtil.keyB16toB32(RFC_HEX_KEY), 4L, 0));
        System.assert(otpUtil.validateHOTP('254676', otpUtil.keyB16toB32(RFC_HEX_KEY), 5L, 0));
        System.assert(otpUtil.validateHOTP('287922', otpUtil.keyB16toB32(RFC_HEX_KEY), 6L, 0));
        System.assert(otpUtil.validateHOTP('162583', otpUtil.keyB16toB32(RFC_HEX_KEY), 7L, 0));
        System.assert(otpUtil.validateHOTP('399871', otpUtil.keyB16toB32(RFC_HEX_KEY), 8L, 0));
        System.assert(otpUtil.validateHOTP('520489', otpUtil.keyB16toB32(RFC_HEX_KEY), 9L, 0));
        try {
            otpUtil.validateHOTP('520489', otpUtil.keyB16toB32(RFC_HEX_KEY), 32768L, 0);
        } catch (Exception ex) {
        }
    }
}