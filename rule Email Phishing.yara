rule  Email_Phishing : mail 
{
    meta:

      description = "Email Phishing"
      author = "Julio Papaqui"

    strings:
        $S1	= "Update account now" ascii wide nocase
        $S2	= "update you password" fullword nocase wide
        $S3	= "Email Suspension" nocase
        $S4	= "Verify your account" nocase
        $S5	= "Security Notice" nocase
        $S6	= "Urgent Request" nocase
        $S7	= "Payment Status" nocase
        $S8	= "aguinaldo" nocase
        $S9	= "bono" nocase
        $S10 = "prestaciones" nocase
        $S11 = "adeudos" fullword nocase
        $S12 = "verificación de contraseña" nocase ascii wide
        $S13 = "Alerta de seguridad" nocase fullword
        $S14 = "Cambio de contraseña" nocase
        $S15 = "Política de vacaciones" nocase
        $S16 = "There is an overdue payment" nocase
        $S17 = "cambie su contraseña de inmediato" nocase
        $S18 = "overdue payment" nocase
        $S19 = "subscription expires" nocase
        $S20 = "365 Account Activity" nocase
        $S21 = "365 Message Center" nocase
        $S22 = "365 Subscription Expires" nocase
        $S23 = "A user account was created" nocase
        $S24 = "renew your password" nocase
        $S25 = "account has been compromised" nocase
        $S26 = "reset your password" fullword nocase
        $S27 = "account is suspended" nocase
        $S28 = "account locked" nocase
        $S29 = "account to be disabled" nocase
        $S30 = "Account Urgently" nocase
        $S31 = "account will be closed" nocase
        $S32 = "AccountUpdate" nocase
        $S33 = "acknowledge a purchase:" nocase
        $S34 = "Acɕɵunt" nocase
        $S35 = "attached document to read" nocase
        $S36 = "attached Secured" nocase
        $S37 = "reset your password" fullword nocase
        $S38 = "Caller-Id" ascii wide nocase
        $S39 = "CallerId" nocase
        $S40 = "Confirm your email address" nocase
        $S41 = "Email account has been" nocase 
        $S42 = "update your password" nocase
        $S43 = "check here:" ascii wide nocase
        $S44 = "email quarantine" nocase
        $S45 = "emails in quarantine" nocase
        $S46 = "CLICK HERE TO ACTIVATE" nocase
        $S47 = "Click on quarantine" nocase
        $S48 = "failure to confirm activity" nocase
        $S49 = "failure to update your account" wide nocase
        $S50 = "Community Intersections" nocase
        $S51 = "Failure to verify" nocase
        $S52 = "in account suspension" nocase
        $S53 = "Confirm your email address" nocase
        $S54 = "High Alert"
        $S55 = "IT Help Desk" wide nocase
        $S56 = "need to re-verify" nocase
        $S57 = "upgraded our security services"nocase
        $S58 = "uploaded using Microsft" nocase
        $S59 = "uploaded using OneDrive" nocase
        $S60 = "Urgent reply please"
       
        
    condition:
        any of ($S*)
}