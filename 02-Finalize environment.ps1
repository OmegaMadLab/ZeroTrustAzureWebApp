$envPrefix = "ZeroTrust"
$rgName = "$envPrefix-RG"
$location = "italynorth"
$webAppUri = "zerotrust.omegamadlab.it"

# KV management
$kvUpn = Read-host -Prompt "Please provide your user principal name (UPN) for the Key Vault access policy"
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
$kv | Set-AzKeyVaultAccessPolicy -UserPrincipalName $kvUpn -PermissionsToCertificates all -PermissionsToSecrets all

$usrMsi = New-AzUserAssignedIdentity -ResourceGroupName $rgName -Name "KvAccess-ManagedIdentity" -Location $location
$kv | Set-AzKeyVaultAccessPolicy -ObjectId $usrMsi.PrincipalId -PermissionsToCertificates get -PermissionsToSecrets get -BypassObjectIdValidation

# Upload certificate for the webapp to the Key Vault
$certName = Read-host -Prompt "Please provide the name of your certificate file (ex. zerotrust.pfx)"
$certPwd = Read-Host -Prompt "Please provide the password for the certificate" -AsSecureString
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
$webAppCert = Import-AzKeyVaultCertificate -VaultName $kv.VaultName -Name "zerotrust" -FilePath ".\$certName" -Password $certPwd

# Add the custom domain to the webapp
$webApp = Get-AzWebApp -ResourceGroupName $rgName | Select-Object -First 1
Write-Host "Create the following record in the public DNS zone of your domain:"
Write-Host "Record type:    TXT"
Write-Host "Record name:    asuid.$($webAppUri)"
Write-Host "Record value:   $($webapp.CustomDomainVerificationId)"
Read-Host -Prompt "Press Enter when ready to continue"

Set-AzWebApp -HostNames @($webAppUri, $webApp.DefaultHostName) `
    -ResourceGroupName $rgName -Name $webApp.Name

# Map the KV certificate to the webapp and create an access policy for the App Service principal ID
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
$kv | Set-AzKeyVaultAccessPolicy -ObjectId "18f3f342-e96f-4eae-b3aa-2d0a533ce89a" -PermissionsToCertificates get -PermissionsToSecrets get -BypassObjectIdValidation

# You might face permission issues while doing this. Eventually complete the task manually in the Azure Portal
Import-AzWebAppKeyVaultCertificate -ResourceGroupName $rgName `
  -WebAppName $webApp.Name -CertName $webAppCert.Name -KeyVaultName $webAppCert.VaultName

New-AzWebAppSSLBinding -ResourceGroupName $rgName -WebAppName $webApp.Name `
    -Name $webAppUri -Thumbprint $webAppCert.Thumbprint -SslState SniEnabled

# Generate a root and intermediate CA certificates for the FW
# OpenSSL needed - use it from the Azure CloudShell, or install it (ex. winget install FireDaemon.Openssl)
.\cert.ps1
openssl x509 -inform PEM -in rootCA.crt -outform DER -out rootCA.cer

# Upload the intermediate CA certificate to the Key Vault
$certName = Read-host -Prompt "Please provide the name of your certificate file (ex. interCA.pfx)"
$certPwd = Read-Host -Prompt "Please provide the password for the certificate" -AsSecureString
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
Import-AzKeyVaultCertificate -VaultName $kv.VaultName -Name "interCA" -FilePath ".\$certName" -Password $certPwd

# App Gateway
$vnet = Get-AzVirtualNetwork -Name "SPOKE-VNET" -ResourceGroupName $rgName
$subnet = Get-AzVirtualNetworkSubnetConfig -Name "wafSubnet" -VirtualNetwork $vnet
$webApp = Get-AzWebApp -ResourceGroupName $rgName | Select-Object -First 1
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
$certSecret = Get-AzKeyVaultSecret -VaultName $kv.VaultName -Name 'zerotrust'
$certSecretId = $certSecret.Id.Replace($certSecret.Version, "")
$pip = Get-AzPublicIpAddress -Name "WAF-PIP" -ResourceGroupName $rgName
$usrId = Get-AzUserAssignedIdentity -ResourceGroupName $rgName | Select-Object -First 1

$ipConfig = New-AzApplicationGatewayIPConfiguration -Name "appGwIpConfig" -Subnet $subnet
$frontendPort = New-AzApplicationGatewayFrontendPort -Name "appGwFrontendPort" -Port 443
$frontendPublicIp = New-AzApplicationGatewayFrontendIPConfig -Name "appGwFrontendPublicIp" -PublicIPAddress $pip
$backendAddressPool = New-AzApplicationGatewayBackendAddressPool -Name "appGwBackendPool" -BackendFqdns $webAppUri
$appGwSslCert = New-AzApplicationGatewaySslCertificate -Name "zerotrustGwSslCert" -KeyVaultSecretId $certSecretId
$backendHttpSettings = New-AzApplicationGatewayBackendHttpSettings -Name "appGwBackendHttpSettings" -Port 443 -Protocol Https -CookieBasedAffinity Enabled -RequestTimeout 30 -HostName $webAppUri
$listener = New-AzApplicationGatewayHttpListener -Name "appGwHttpListenerPublic" -Protocol Https -SslCertificate $appGwSslCert -FrontendIPConfiguration $frontendPublicIp -FrontendPort $frontendPort 
$rule = New-AzApplicationGatewayRequestRoutingRule -Name "rule" -RuleType Basic -BackendHttpSettings $backendHttpSettings -HttpListener $listener -BackendAddressPool $backendAddressPool -Priority 1
$sku = New-AzApplicationGatewaySku -Name Standard_v2 -Tier Standard_v2 -Capacity 1

$policySetting = New-AzApplicationGatewayFirewallPolicySetting `
                    -Mode Prevention `
                    -State Enabled `
                    -MaxRequestBodySizeInKb 100 `
                    -MaxFileUploadInMb 100
$managedRuleSet = New-AzApplicationGatewayFirewallPolicyManagedRuleSet -RuleSetType "Microsoft_DefaultRuleSet" `
                    -RuleSetVersion "2.1"
$wafPolicy = New-AzApplicationGatewayFirewallPolicy `
                    -Name "WAF-POLICY" `
                    -ResourceGroup $rgName `
                    -Location $location `
                    -PolicySetting $PolicySetting `
                    -ManagedRule (New-AzApplicationGatewayFirewallPolicyManagedRule -ManagedRuleSet $managedRuleSet)

$appGw = New-AzApplicationGateway -Name "APPGW" -ResourceGroupName $rgName -Location $location -BackendAddressPools $backendAddressPool `
            -BackendHttpSettingsCollection $backendHttpSettings -FrontendIpConfigurations $frontendPublicIp -GatewayIpConfigurations $ipConfig `
            -FrontendPorts $frontendPort -HttpListeners $listener -RequestRoutingRules $rule -Sku $sku `
            -SslCertificates $appGwSslCert -UserAssignedIdentityId $usrId.Id


$appGw.FirewallPolicy = $wafPolicy
$appGw.Sku = (New-AzApplicationGatewaySku -Name WAF_v2 -Tier WAF_v2 -Capacity 1)
Set-AzApplicationGateway -ApplicationGateway $appGw

$trustedRootCert = New-AzApplicationGatewayTrustedRootCertificate -Name "fwRootCA" -CertificateFile ./rootCA.cer
$backendHttpSettings = New-AzApplicationGatewayBackendHttpSettings -Name "appGwBackendHttpSettings" -Port 443 -Protocol Https -CookieBasedAffinity Enabled -RequestTimeout 30 -HostName $webAppUri -TrustedRootCertificate $trustedRootCert

$appGw.TrustedRootCertificates = $trustedRootCert
$appGw.BackendHttpSettingsCollection = $backendHttpSettings
Set-AzApplicationGateway -ApplicationGateway $appGw

# Attach spoke route table to wafSubnet
$vnet = Get-AzVirtualNetwork -Name "SPOKE-VNET" -ResourceGroupName $rgName
$subnets = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet
($subnets | Where-Object Name -eq "wafSubnet").RouteTable = Get-AzRouteTable -Name "WAF-RT" -ResourceGroupName $rgName
($subnets | Where-Object Name -ne "wafSubnet") | ForEach-Object { $_.RouteTable = Get-AzRouteTable -Name "APP-RT" -ResourceGroupName $rgName }
$vnet | Set-AzVirtualNetwork

# Firewall Policy
$usrId = Get-AzUserAssignedIdentity -ResourceGroupName $rgName | Select-Object -First 1
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
$certSecret = Get-AzKeyVaultSecret -VaultName $kv.VaultName -Name 'interCA'
$certSecretId = $certSecret.Id.Replace($certSecret.Version, "")
$fwPolicy = Get-AzFirewallPolicy -Name "AZFW-POLICY" -ResourceGroupName $rgName
$fwPolicy | Set-AzFirewallPolicy -ThreatIntelMode Deny `
                -IntrusionDetection (New-AzFirewallPolicyIntrusionDetection -Mode Deny -PrivateRange @("192.168.0.0/24", "10.0.0.0/22") ) `
                -DnsSetting (New-AzFirewallPolicyDnsSetting -EnableProxy) `
                -UserAssignedIdentityId $usrId.Id `
                -TransportSecurityName "zerotrust-intermediateCA" `
                -TransportSecurityKeyVaultSecretId $certSecretId

# Allow from waf subnet to webapp fqdn with TLS inspection
$appRule = New-AzFirewallPolicyApplicationRule -Name "Allow-ZeroTrustWebApp" `
            -SourceAddress "192.168.1.0/24" `
            -TargetFqdn $webAppUri `
            -Protocol "https:443" `
            -TerminateTLS

$ruleCollection = New-AzFirewallPolicyFilterRuleCollection  -Name "Allow-ZeroTrustWebApp" `
                    -Priority 100 `
                    -ActionType "Allow" `
                    -Rule $appRule

Set-AzFirewallPolicyRuleCollectionGroup -Name "ZeroTrustAppRule" `
    -RuleCollection $ruleCollection `
    -Priority 100 -FirewallPolicyObject $fwPolicy
                