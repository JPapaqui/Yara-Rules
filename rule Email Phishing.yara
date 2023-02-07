rule  Email_Phishing : mail 
{
    meta:

      description = "Email Phishing"
      author = "Julio Papaqui"

    strings:
        $S1	= "onedrive" ascii wide nocase
        $S2	= "subscription expires" fullword nocase wide
        $S3	= "Garden Oaks" nocase
        $S4	= "365 Account Activity" nocase
        $S5	= "365 Message Center" nocase
        $S6	= "365 Subscription Expires" nocase
        $S7	= "a quote by the due" nocase
        $S8	= "A user account was created" nocase
        $S9	= "access your voicemail" nocase
        $S10 = "account has been compromised" nocase
        $S11 = "account is suspended" fullword nocase
        $S12 = "account locked" nocase
        $S13 = "account to be disabled" nocase fullword
        $S14 = "Account Urgently" nocase
        $S15 = "account will be closed" nocase
        $S16 = "AccountUpdate" nocase
        $S17 = "expire" nocase
        $S18 = "acknowledge a purchase:" nocase
        $S19 = "acquire contact details" nocase
        $S20 = "Acɕɵunt" nocase
        $S21 = "Account" nocase
        $S22 = "Admin Member Services" nocase
        $S23 = "advice back" nocase
        $S24 = "renew your password" nocase
        $S25 = "and account closure" nocase
        $S26 = "reset your password" fullword nocase
        $S27 = "aSecuredDocumentsvia" nocase
        $S28 = "attached document to read" nocase
        $S29 = "attached Secured" nocase
        $S30 = "available at the office" nocase
        $S31 = "available for an urgent" nocase
        $S32 = "Banking" nocase
        $S33 = "Be warned" nocase
        $S34 = "Severity" nocase
        $S35 = "blatant spam messages" nocase
        $S36 = "reset your password" ascii wide nocase
        $S37 = "reset your password" fullword
        $S38 = "Caller-Id" ascii wide nocase
        $S39 = "CallerId" nocase
        $S40 = "can't take calls" ascii wide nocase
        $S41 = "cannot take my calls" nocase
        $S42 = "update your password" nocase
        $S43 = "check here:" ascii wide nocase
        $S44 = "claim please contact below" nocase
        $S45 = "Cleaning Services" nocase
        $S46 = "CLICK HERE TO ACTIVATE" nocase
        $S47 = "Click on quarantine" nocase
        $S48 = "Client Acquisition" nocase
        $S49 = "Collections.pdf" ascii wide nocase
        $S50 = "Community Intersections" nocase
        $S51 = "complete a task for"nocase
        $S52 = "completely restore process" nocase
        $S53 = "Confirm your email address" nocase
        $S54 = "High Alert"
        $file1 = "attach is my resume" nocase
        $file2 = "PDF file is my resume" fullword 
        $file3 = "Attach" nocase
        $file4 = "Pdf" nocase
        
    condition:
        any of ($S*) and any of ($file*)
}