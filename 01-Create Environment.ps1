$envPrefix = "AzureDay-2024"
$location = "italynorth"
$rgName = "$envPrefix-RG"
$dnsDomainName = "omegamadlab.it"
$dnsDomainARecordName = "zerotrust"

$rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
if(-not $rg) {
    $rg = New-AzResourceGroup -Name $rgName -Location $location
}

New-AzResourceGroupDeployment -ResourceGroupName $rgName `
    -TemplateFile .\main.bicep `
    -envPrefix $envPrefix `
    -dnsDomainName $dnsDomainName `
    -dnsDomainARecordName $dnsDomainARecordName
