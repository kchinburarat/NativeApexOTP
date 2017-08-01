/*
 * Block comments with details of changes
 */
public class OTPManager
{
    public OTPManager(){ }
    protected final string USER_PREFIX    = User.sObjectType.getDescribe().getKeyPrefix();
    protected final string ACCOUNT_PREFIX = Account.sObjectType.getDescribe().getKeyPrefix();
    protected final integer RETRY_LIMIT = 5;
    protected final integer EXPIRE_MIN = 15;
    private User getUser(string userId) {
        User currentUser = [Select id , AccountId , ContactId From user Where  Id = : userId ];
        return currentUser;
    }
    /*
	* @description Returns OTP_Master__c Object
	* @param requestId the id of the user to look up
	* @return OTP_Master__c
	* @example
	*  OTP_Master__c otpms = createNewOtpMaster(user.Id);
	*/
    private OTP_Master__c createNewOtpMaster(Id requestId) {
        string userId;
        string accountId;
        User user;
        if (((string)requestId).startsWith(USER_PREFIX)) {
            // User
            user 		= getUser(requestId);
            userId 		= user.Id;
            accountId 	= user.AccountId;
        } else {
            // Account
            userId = null;
            accountId = requestId;
        }
        OTP_Master__c otpms =  (OTP_Master__c)OTP_Master__c.sObjectType.newSObject(null, true);
        otpms.User__c    = userId;
        otpms.Account__c = accountId;
        otpms.Secret_Key__c = OtpUtil.generateBase32Key();//<<==  Create particular user key
        system.debug('Secret Key : ' + otpms.Secret_Key__c);
        //Insert
        insert otpms;

        return otpms;
    }
    /*
	* @description get OTP Master for user
	* @param requestId the id of the user to look up
	* @return OTP_Master__c
	* @example
	*  OTP_Master__c otpms = getUserOtpMaster(user.Id);
	*/
    private OTP_Master__c selectUserOtpMaster(Id requestId) {
        OTP_Master__c otpms ;
        string filter = requestId;
        if (((string)requestId).startsWith(USER_PREFIX)) {
            User user 		= getUser(requestId);
            filter = user.AccountId;
        }
        List<OTP_Master__c> lstOtpms = [select Id , User__c , Account__c, Secret_Key__c , Counter__c  From OTP_Master__c Where Account__c = : filter limit 1];
        if (lstOtpms.size() > 0) {
            otpms = lstOtpms[0];
        }
        return otpms;
    }
    /*
	* @description get OTP Master for user or create new record if not existing record found
	* @param requestId the id of the user to look up
	* @return OTP_Master__c
	* @example
	*  OTP_Master__c otpms = getUserOtpMaster(user.Id);
	*/
    public OTP_Master__c getUserOtpMaster(Id requestId) {
        OTP_Master__c otpms;

        otpms = selectUserOtpMaster(requestId);
        //Flow 1) Found OTP Master for specific user id
        if (null != otpms) {
            if (((string)requestId).startsWith(USER_PREFIX) && null == otpms.User__c) {
                otpms.User__c = requestId;
                update otpms;
            }
            return otpms;
        }
        //Flow 2) Create new OTP Master for new request
        else {
            otpms = createNewOtpMaster(requestId);
        }
        return otpms;
    }

    private OTP__c getCurrentOTP(Id requestId , string otpCode) {

        string filter = requestId;
        if (((string)requestId).startsWith(USER_PREFIX)) {
            User user 		= getUser(requestId);
            filter = user.AccountId;
        }

        List<OTP__c> otps = [select Id, Expire_DateTIme__c, Is_Expired__c, Is_Used__c , Issue_DateTime__c ,
                             OTP_Code__c, OTP_Master__c , OTP_Master__r.User__c, Retry__c
                             From OTP__c
                             where OTP_Code__c = : otpCode and OTP_Master__r.Account__c = : filter];

        if (otps.size() > 0) return otps[0];
        return null;
    }

    private OTP__c createOtpRecord(Id otpMasterId , string otpCode) {
        OTP__c otp =  (OTP__c)OTP__c.sObjectType.newSObject(null, true);
        otp.OTP_Master__c = otpMasterId;
        otp.OTP_Code__c = otpCode;
        DateTime cdt = Datetime.now();
        otp.Issue_DateTime__c = cdt;
        otp.Expire_DateTIme__c = cdt.addMinutes(EXPIRE_MIN);
        insert otp;

        return otp;
    }

    private OTP_Master__c increaseCounter(OTP_Master__c otpms) {
        otpms.Counter__c += 1;
        update otpms;
        return otpms;
    }

    @testVisible
    private string createOTP(OTP_Master__c otpms) {
        string otpCode;
        Long counter = (Long) otpms.Counter__c;
        system.debug('User key : ' + otpms.Secret_Key__c);
        system.debug('Current Couter : ' + counter);
        otpCode = OtpUtil.generateOTP(otpms.Secret_Key__c, counter);
        system.debug('New OTP : ' + otpCode);
        return otpCode;
    }

    /**
	* @description 
	* @param requestId is account id or userid
	* @return OTP__c record
	*/ 
    public OTP__c requestOTP(Id requestId) {
        //1 Check current OTP and Is It valide
        OTP_Master__c otpms = getUserOtpMaster(requestId);
        string otpCode = createOTP(otpms);
        system.debug('Current OTP : ' + otpCode);
        //Get OTP Record
        OTP__c otpRecord = getCurrentOTP(requestId, otpCode);
        DateTime cdt = Datetime.now();

        //Flow 1)  Create New OTP Record
        if (null == otpRecord ) {
            otpRecord = createOtpRecord(otpms.Id , otpCode);
        }
        //Flow 2)  Existing OTP Record
        else {
            // Condition 2.1 ) OTP Record invalid
            if (otpRecord.Is_Used__c || otpRecord.Is_Expired__c) {
                // Create New Record
                otpms = increaseCounter(otpms);
                otpCode = createOTP(otpms);
                //>Creat new OTP
                otpRecord = createOtpRecord(otpms.Id , otpCode);

            } else { // Condition 2.2 ) OTP Still Valid
                //>Time Condition
                Long milliseconds = otpRecord.Expire_DateTime__c.getTime()  - cdt.getTime() ;
                Long seconds = milliseconds / 1000;
                Long minutes = seconds / 60;
                //>Retry Condition
                boolean isExceedLimit = otpRecord.Retry__c > RETRY_LIMIT ? true : false;
                // Condition 2.2.1 ) Valide less than 1 min or exceed retry
                if (minutes < 1L/* less than 1 min*/  ||  isExceedLimit) {
                    if (isExceedLimit) {otpRecord.Is_Used__c = true;}
                    if (minutes < 1L) {otpRecord.Is_Expired__c = true;}
                    update otpRecord;
                    otpms = increaseCounter(otpms);
                    otpCode = createOTP(otpms);
                    //>Creat new OTP
                    otpRecord = createOtpRecord(otpms.Id , otpCode);
                }
            }
        }
        return otpRecord;
    }
    public boolean verifyOTP(Id requestId, string otpCode) {
        Datetime cdt = DateTime.now();
        //System Current OTP
        OTP_Master__c otpms = getUserOtpMaster(requestId);
        string userCurrentOtp = createOTP(otpms);
        OTP__c otp = getCurrentOTP( requestId , userCurrentOtp);
        if (null == otp) {
            system.debug('Please request the new OTP');
            return false;
        } else if (otp.Is_Used__c) {
            system.debug('cannot use old OTP Code ');
            return false;
        } else {
            boolean isMatch    = userCurrentOtp == otpCode;
            boolean isExpire   = cdt > otp.Expire_DateTIme__c;
            boolean isMaxReTry = otp.Retry__c >= RETRY_LIMIT;
            boolean isUsed = otp.Is_Used__c;
            if (isExpire) {
                otp.Is_Expired__c = true;
                otp.Is_Used__c = true;
                update otp;
                system.debug('OTP Code was expired ');
                return false;
            }
            if (isMaxReTry) {
                otp.Is_Used__c = true;
                update otp;
                system.debug('OTP Code was hit max retry ');
                return false;
            }

            if (!isMatch) {
                otp.Retry__c += 1;
                system.debug('OTP Code miss match ');
                update otp;
                return false;
            }
            if (isUsed) {
                system.debug('cannot use old OTP Code ');
                return false;
            }
        }
        //Every Things OK

        system.debug('Verify success ');
        otp.Is_Expired__c = false;
        otp.Is_Used__c = true;
        update otp;
        increaseCounter(otpms);
        system.debug('Counter : ' + otpms.Counter__c);
        return true;
    }


}
