$envPrefix = "AzureDay2024"
$rgName = "$envPrefix-RG"
$location = "italynorth"
$wafInternalIp = "192.168.10.100"
$webAppUri = "zerotrust.omegamadlab.it"

# KV management
$kvUpn = Read-host -Prompt "Please provide your user principal name (UPN) for the Key Vault access policy"
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
$kv | Set-AzKeyVaultAccessPolicy -UserPrincipalName $kvUpn -PermissionsToCertificates all -PermissionsToSecrets all

$usrMsi = New-AzUserAssignedIdentity -ResourceGroupName $rgName -Name "KvAccess-ManagedIdentity" -Location $location
$kv | Set-AzKeyVaultAccessPolicy -ObjectId $usrMsi.PrincipalId -PermissionsToCertificates get -PermissionsToSecrets get

# Upload certificate for the webapp
$certName = Read-host -Prompt "Please provide the name of your certificate file (ex. zerotrust.pfx)"
$certPwd = Read-Host -Prompt "Please provide the password for the certificate" -AsSecureString
$kv = Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -First 1
Import-AzKeyVaultCertificate -VaultName $kv.VaultName -Name "zerotrust" -FilePath ".\$certName" -Password $certPwd

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
$frontendIp = New-AzApplicationGatewayFrontendIPConfig -Name "appGwFrontendIp" -SubnetId $subnet.Id -PrivateIPAddress $wafInternalIp
$backendAddressPool = New-AzApplicationGatewayBackendAddressPool -Name "appGwBackendPool" -BackendFqdns $webApp.DefaultHostName
$appGwSslCert = New-AzApplicationGatewaySslCertificate -KeyVaultSecretId $certSecretId -Name $certSecret.Name
$listener1 = New-AzApplicationGatewayHttpListener -Name "appGwHttpListenerPublic" -Protocol Https -SslCertificate $appGwSslCert -FrontendIPConfiguration $frontendPublicIp -FrontendPort $frontendPort 
$rule1 = New-AzApplicationGatewayRequestRoutingRule -Name "rule1" -RuleType Basic -BackendHttpSettings $backendHttpSettings -HttpListener $listener1 -BackendAddressPool $backendAddressPool -Priority 1
$listener2 = New-AzApplicationGatewayHttpListener -Name "appGwHttpListenerInternal" -Protocol Https -SslCertificate $appGwSslCert -FrontendIPConfiguration $frontendIp -FrontendPort $frontendPort 
$rule2 = New-AzApplicationGatewayRequestRoutingRule -Name "rule2" -RuleType Basic -BackendHttpSettings $backendHttpSettings -HttpListener $listener2 -BackendAddressPool $backendAddressPool -Priority 2
$sku = New-AzApplicationGatewaySku -Name Standard_v2 -Tier Standard_v2 -Capacity 1

$policySetting = New-AzApplicationGatewayFirewallPolicySetting `
                    -Mode Prevention `
                    -State Enabled `
                    -MaxRequestBodySizeInKb 100 `
                    -MaxFileUploadInMb 100
$managedRuleSet = New-AzApplicationGatewayFirewallPolicyManagedRuleSet -RuleSetType "OWASP" `
                    -RuleSetVersion "3.2"
$wafPolicy = New-AzApplicationGatewayFirewallPolicy `
                    -Name "WAF-POLICY" `
                    -ResourceGroup $rgName `
                    -Location $location `
                    -PolicySetting $PolicySetting `
                    -ManagedRule (New-AzApplicationGatewayFirewallPolicyManagedRule -ManagedRuleSet $managedRuleSet)

$appGw = New-AzApplicationGateway -Name "APPGW" -ResourceGroupName $rgName -Location $location -BackendAddressPools $backendAddressPool `
            -BackendHttpSettingsCollection $backendHttpSettings -FrontendIpConfigurations $frontendIp, $frontendPublicIp -GatewayIpConfigurations $ipConfig `
            -FrontendPorts $frontendPort -HttpListeners $listener1, $listener2 -RequestRoutingRules $rule1, $rule2 -Sku $sku `
            -SslCertificates $appGwSslCert -UserAssignedIdentityId $usrId.Id -TrustedRootCertificate $trustedRootCert


$appGw.FirewallPolicy = $wafPolicy
$appGw.Sku = (New-AzApplicationGatewaySku -Name WAF_v2 -Tier WAF_v2 -Capacity 1)
Set-AzApplicationGateway -ApplicationGateway $appGw

$trustedRootCert = New-AzApplicationGatewayTrustedRootCertificate -Name "trustedRootCA" -CertificateFile .\rootCA.cer
$backendHttpSettings = New-AzApplicationGatewayBackendHttpSettings -Name "appGwBackendHttpSettings" -Port 443 -Protocol Https -CookieBasedAffinity Enabled -RequestTimeout 30 -PickHostNameFromBackendAddress -TrustedRootCertificate $trustedRootCert

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
                -IntrusionDetection (New-AzFirewallPolicyIntrusionDetection -Mode Deny) `
                -DnsSetting (New-AzFirewallPolicyDnsSetting -EnableProxy) `
                -UserAssignedIdentityId $usrId.Id `
                -TransportSecurityName "zerotrust-intermediateCA" `
                -TransportSecurityKeyVaultSecretId $certSecretId

$rule1 = New-AzFirewallPolicyNetworkRule -Name "waf-to-app" `
            -SourceAddress "192.168.0.0/24" `
            -DestinationAddress "192.168.10.0/24" `
            -DestinationPort "443" `
            -Protocol "TCP"
$rule2 = New-AzFirewallPolicyNetworkRule -Name "app-to-waf" `
            -SourceAddress "192.168.10.0/24" `
            -DestinationAddress "192.168.0.0/24" `
            -DestinationPort "443" `
            -Protocol "TCP"
$ruleCollection = New-AzFirewallPolicyFilterRuleCollection  -Name "Allow-app" `
                    -Priority 100 `
                    -ActionType "Allow" `
                    -Rule $rule1, $rule2
Set-AzFirewallPolicyRuleCollectionGroup -Name "Recipe02-07-Network" `
    -RuleCollection $ruleCollection `
    -Priority 100 -FirewallPolicyObject $fwPolicy
                