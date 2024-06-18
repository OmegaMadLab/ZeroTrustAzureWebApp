$envPrefix = "AzureDay2024"
$location = "italynorth"
$rgName = "$envPrefix-RG"
$dnsDomainName = "omegamadlab.it"
$dnsDomainARecordName = "zerotrust"
$dnsDomainARecordValue = "192.168.10.100"

$rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
if(-not $rg) {
    $rg = New-AzResourceGroup -Name $rgName -Location $location
}

New-AzResourceGroupDeployment -ResourceGroupName $rgName `
    -TemplateFile .\main.bicep `
    -envPrefix $envPrefix `
    -dnsDomainName $dnsDomainName `
    -dnsDomainARecordName $dnsDomainARecordName `
    -dnsDomainARecordValue $dnsDomainARecordValue
