$subnetMask=(Get-ClusterNetwork).AddressMask

Add-ClusterResource -Name "Cluster IP Address 2" -Group "Cluster Group" -ResourceType "IP Address" 

Get-ClusterResource -Name "Cluster IP Address 2"| 
Set-ClusterParameter -Multiple @{
                "Address" = "10.0.1.8"
                "SubnetMask" = $subnetMask
                "EnableDhcp" = 0
                "OverrideAddressMatch" = 1
            }

Set-ClusterResourceDependency -Resource "Cluster Name" -Dependency "([Cluster IP Address]) and ([Cluster IP Address 2])"
