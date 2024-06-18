param location string = resourceGroup().location
param envPrefix string
param adminUsername string = 'adminUser'
@secure()
param adminPassword string = newGuid()
param dnsDomainName string
param dnsDomainARecordName string
param dnsDomainARecordValue string

var spokeSubnetList = [
  {
    name: 'wafSubnet'
    subnetPrefix: '192.168.0.0/24'
  }
  {
    name: 'appSubnet'
    subnetPrefix: '192.168.10.0/24'
  }
  {
    name: 'clientSubnet'
    subnetPrefix: '192.168.20.0/24'
  }
]

var rtList = [
  {
    name: 'WAF-RT'
    routes: [
      {
        name: 'to-app'
        addressPrefix: first(filter(spokeSubnetList, s => s.name == 'appSubnet')).subnetPrefix
      }
    ]
  }
  {
    name: 'APP-RT'
    routes: [
      {
        name: 'to-waf'
        addressPrefix: first(filter(spokeSubnetList, s => s.name == 'wafSubnet')).subnetPrefix
      }
    ]
  }
]

resource hubVnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: 'HUB-VNET'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/22'
      ]
    }
  }
}

resource fwSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-04-01' = {
  name: 'AzureFirewallSubnet'
  parent: hubVnet
  properties: {
    addressPrefix: '10.0.0.0/26'
  }
}

resource fwPolicy 'Microsoft.Network/firewallPolicies@2023-09-01' = {
  name: 'AZFW-POLICY'
  location: location
  properties: {
    threatIntelMode: 'Alert'
    sku: {
      tier: 'Premium'
    }
  }
}

resource fwPip 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: 'AZFW-PIP'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource fw 'Microsoft.Network/azureFirewalls@2023-09-01' = {
  name: 'AZFW'
  location: location
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Premium'
    }
    ipConfigurations: [
      {
        name: 'AzureFirewallIpConfig'
        properties: {
          subnet: {
            id: fwSubnet.id
          }
          publicIPAddress: {
            id: fwPip.id
          }
        }
      }
    ]
    firewallPolicy: {
      id: fwPolicy.id
    }
  }
}

output fwPublicIP string = fwPip.properties.ipAddress
output fwPrivateIP string = fw.properties.ipConfigurations[0].properties.privateIPAddress

resource rt 'Microsoft.Network/routeTables@2023-04-01' = [for rt in rtList: {  
  name: rt.name
  location: location
  properties: {
    routes: [
      for route in rt.routes: {
        name: route.name
        properties: {
          addressPrefix: route.addressPrefix
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: fw.properties.ipConfigurations[0].properties.privateIPAddress
        }
      }
    ]
    disableBgpRoutePropagation: true
  }
}]

resource spokeVnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: 'SPOKE-VNET'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '192.168.0.0/19'
      ]
    }
  }
}

@batchSize(1)
resource spokeSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-04-01' = [for (subnet, i) in spokeSubnetList: {
  name: subnet.name
  parent: spokeVnet
  properties: {
    privateEndpointNetworkPolicies: 'Enabled'
    addressPrefix: subnet.subnetPrefix
    routeTable:i == 0 ? null : { id: rt[1].id }
  }
}]

resource peeringH2S 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-04-01' = {
  name: 'hub-to-spoke-peer'
  parent: hubVnet
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
    remoteVirtualNetwork: {
      id: spokeVnet.id
    }
  }
  dependsOn: [
    spokeSubnet[0]
    spokeSubnet[1]
    spokeSubnet[2]
  ]
}

resource peeringS2H 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-04-01' = {
  name: 'spoke-to-hub-peer'
  parent: spokeVnet
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
    remoteVirtualNetwork: {
      id: hubVnet.id
    }
  }
  dependsOn: [
    fwSubnet
  ]
}

resource wafIp 'Microsoft.Network/publicIPAddresses@2019-11-01' = {
  name: 'WAF-PIP'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'static'
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2020-12-01' = {
  name: 'WEBAPP-ASP'
  location: location
  sku: {
    name: 'S1'
    capacity: 1
  }
  properties: {
    reserved: true
  }
  kind: 'linux'
}

resource webApp 'Microsoft.Web/sites@2020-12-01' = {
  name: take('${envPrefix}-${guid(resourceGroup().id)}', 20)
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      appSettings: []
      linuxFxVersion: 'DOCKER|httpd:latest'
    }
    httpsOnly: true
  }
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2021-02-01' = {
  name: 'WEBAPP-PE'
  location: location
  properties: {
    subnet: {
      id: spokeSubnet[1].id
    }
    privateLinkServiceConnections: [
      {
        name: 'WEBAPP-ServiceConnection'
        properties: {
          privateLinkServiceId: webApp.id
          groupIds: [
            'sites'
          ]
        }
      }
    ]
  }
}

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.azurewebsites.net'
  location: 'global'
}

resource privateDnsZoneHubLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: 'hub-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: hubVnet.id
    }
  }
}

resource privateDnsZoneSpokeLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: 'spoke-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: spokeVnet.id
    }
  }
}

resource privateEndpointDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  name: 'WEBAPP-PE-DNSZoneGroup'
  parent: privateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'default'
        properties: {
          privateDnsZoneId: privateDnsZone.id
        }
      }
    ]
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: take('${envPrefix}-kv-${guid(resourceGroup().id)}', 23)
  location: location
  properties: {
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enabledForDiskEncryption: true
    tenantId: subscription().tenantId
    accessPolicies: [
    ]
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: 'CLIENT-VM-NIC'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipConfig'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: spokeSubnet[2].id
          }
        }
      }
    ]
  }
}

resource windowsVM 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: 'CLIENT-VM'
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'CLIENT-VM'
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        name: 'name'
        caching: 'ReadWrite'
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true    
      }
    }
  }
}

resource splitDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: dnsDomainName
  location: 'global'
}

resource splitDnsZoneSpokeLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: splitDnsZone
  name: 'split-spoke-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: spokeVnet.id
    }
  }
}

resource dnsRecord 'Microsoft.Network/privateDnsZones/A@2020-06-01' = {
  parent: splitDnsZone
  name: dnsDomainARecordName
  properties: {
    ttl: 3600
    aRecords: [
      {
        ipv4Address: dnsDomainARecordValue
      }
    ]
  }
}
