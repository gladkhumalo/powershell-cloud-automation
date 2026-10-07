# Static check definitions. Order here is the report order within each status and severity.
# Baseline values cite the public CISA SCuBA Microsoft Entra ID baseline where a policy matches.
$script:CheckCatalog = [ordered]@{
    'ID-001'     = @{
        Category       = 'Identity'
        Title          = 'MFA is enforced for all users'
        Severity       = 'High'
        Baseline       = @('CISA MS.AAD.3.2v2')
        Recommendation = 'Enable security defaults, or create a Conditional Access policy that requires MFA (preferably an authentication strength) for all users and all resources. Exclude only documented emergency-access accounts, and switch report-only policies to On after reviewing sign-in impact.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength'
    }
    'ID-002'     = @{
        Category       = 'Identity'
        Title          = 'Legacy authentication is blocked'
        Severity       = 'High'
        Baseline       = @('CISA MS.AAD.1.1v1')
        Recommendation = 'Block legacy authentication for all users with Conditional Access (client apps: Exchange ActiveSync clients and Other clients), or enable security defaults. Review sign-in logs for legacy clients before enforcing.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication'
    }
    'ID-003'     = @{
        Category       = 'Identity'
        Title          = 'Members are registered for MFA'
        Severity       = 'Medium'
        Baseline       = @()
        Recommendation = 'Run a registration campaign or a Conditional Access registration policy for unregistered members. Review disabled, shared, and service accounts separately instead of excluding them silently.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign'
    }
    'ID-004'     = @{
        Category       = 'Identity'
        Title          = 'Weak authentication methods are disabled'
        Severity       = 'Medium'
        Baseline       = @('CISA MS.AAD.3.5v2', 'CISA MS.AAD.3.4v1')
        Recommendation = 'Disable SMS, voice call, and email one-time passcode in the authentication methods policy once users have Microsoft Authenticator, passkeys, or FIDO2 keys, and complete the authentication methods migration.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage'
    }
    'ID-005'     = @{
        Category       = 'Identity'
        Title          = 'Self-service password reset is enabled and registered'
        Severity       = 'Low'
        Baseline       = @()
        Recommendation = 'Enable self-service password reset for all users and use combined registration so people register MFA and SSPR methods together. Unregistered users depend on the helpdesk, which is a social-engineering target.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr'
    }
    'PRIV-001'   = @{
        Category       = 'Privileged access'
        Title          = 'Global Administrator count is within range'
        Severity       = 'High'
        Baseline       = @('CISA MS.AAD.7.1v1')
        Recommendation = 'Keep between two and four people able to hold Global Administrator (active, eligible, or through a group), including emergency-access accounts. Move day-to-day administration to least-privileged roles.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    }
    'PRIV-002'   = @{
        Category       = 'Privileged access'
        Title          = 'Administrators are registered for MFA'
        Severity       = 'High'
        Baseline       = @()
        Recommendation = 'Have every administrator register MFA now and enforce MFA for directory roles with Conditional Access. Treat an unregistered administrator as a priority account-takeover risk.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    }
    'PRIV-003'   = @{
        Category       = 'Privileged access'
        Title          = 'Administrators have phishing-resistant methods'
        Severity       = 'Medium'
        Baseline       = @('CISA MS.AAD.3.6v1')
        Recommendation = 'Register FIDO2 security keys, passkeys, or Windows Hello for Business for administrators, then require a phishing-resistant authentication strength for admin roles.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    }
    'PRIV-004'   = @{
        Category       = 'Privileged access'
        Title          = 'Global Administrator access is just-in-time'
        Severity       = 'Medium'
        Baseline       = @('CISA MS.AAD.7.4v1')
        Recommendation = 'Convert permanent Global Administrator assignments to eligible assignments in Privileged Identity Management, with MFA and approval on activation. Keep permanent assignments only for emergency-access accounts.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure'
    }
    'PRIV-005'   = @{
        Category       = 'Privileged access'
        Title          = 'Emergency access is protected from lockout'
        Severity       = 'High'
        Baseline       = @()
        Recommendation = 'Keep at least two cloud-only emergency-access accounts with permanent Global Administrator, exclude at least one from every Conditional Access policy, protect them with FIDO2 keys, and remove exclusions for anyone else.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
    }
    'APP-001'    = @{
        Category       = 'Applications'
        Title          = 'User consent to applications is restricted'
        Severity       = 'High'
        Baseline       = @('CISA MS.AAD.5.2v1')
        Recommendation = "Set user consent to 'Do not allow user consent', or allow consent only for verified publishers and low-impact permissions. Enable the admin consent workflow so users can request access."
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent'
    }
    'APP-002'    = @{
        Category       = 'Applications'
        Title          = 'Users cannot register applications'
        Severity       = 'Medium'
        Baseline       = @('CISA MS.AAD.5.1v1')
        Recommendation = "Set 'Users can register applications' to No and assign the Application Developer role to people who need it."
        Reference      = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions'
    }
    'COLLAB-001' = @{
        Category       = 'External collaboration'
        Title          = 'Guest invitations are restricted'
        Severity       = 'Medium'
        Baseline       = @('CISA MS.AAD.8.2v1')
        Recommendation = 'Limit guest invitations to administrators and the Guest Inviter role, and route other external access through entitlement management or an approval process.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure'
    }
    'COLLAB-002' = @{
        Category       = 'External collaboration'
        Title          = 'Guest directory access is restricted'
        Severity       = 'Low'
        Baseline       = @('CISA MS.AAD.8.1v1')
        Recommendation = 'Restrict guest access to the properties and memberships of their own directory objects unless a documented business need requires broader visibility.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions'
    }
}

$script:StatusRank = @{ Fail = 0; Warn = 1; NotAssessed = 2; Accepted = 3; Pass = 4 }
$script:SeverityRank = @{ High = 0; Medium = 1; Low = 2 }
$script:CheckRank = @{}
$rank = 0
foreach ($checkId in $script:CheckCatalog.Keys) {
    $script:CheckRank[$checkId] = $rank++
}

$script:DefaultThresholds = [ordered]@{
    MinimumGlobalAdmins           = 2
    MaximumGlobalAdmins           = 4
    MfaRegistrationTargetPercent  = 95
    MfaRegistrationMinimumPercent = 80
}
