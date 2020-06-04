$out_file = 'forensic_auto_output.txt'

if (Test-Path $out_file) {
	Write-Output "Output file $out_file already exists! Deleting it..."
	Remove-Item $out_file
}

Class network_list_profiles
{
	[String]$profile_name
	[String]$description
	[int]$managed
	[int]$category
	[datetime]$date_created
	[int]$name_type
	[datetime]$date_last_connected
}

Class network_interfaces
{
	[String]$dhcp_default_gateway = ""
	[String]$dhcp_domain = ""
	[String]$dhcp_ip_address = ""
	[String]$dhcp_subnet_mask = ""
}

$profiles = @()
$interfaces = @()

if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles')
{
	Write-Output 'List of GUIDs of Wireless Access Points' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	try
	{
		$subkey_str = Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
		$subkeys = $subkey_str -split '\r?\n'
		$subkeys = $subkeys | ? {$_ -ne ''}
		foreach ($subkey in $subkeys)
		{
			#Write-Output '[+]  Fetching ' $subkey
			#Write-Output ''
			$temp = 'Registry::' + $subkey | Tee-Object -file $out_file -Append
			$profile_object = New-Object network_list_profiles
			$profile_object.profile_name = (Get-ItemProperty -ErrorAction Ignore $temp)."ProfileName"
			$profile_object.description = (Get-ItemProperty -ErrorAction Ignore $temp)."Description"
			$profile_object.managed = (Get-ItemProperty -ErrorAction Ignore $temp)."Managed"
			$profile_object.category = (Get-ItemProperty -ErrorAction Ignore $temp)."Category"
			$profile_object.date_created = [datetime]::FromFileTime($([System.BitConverter]::ToInt64($(Get-ItemProperty -ErrorAction Ignore $temp)."DateCreated", 0)))
			$profile_object.name_type = (Get-ItemProperty -ErrorAction Ignore $temp)."NameType"
			$profile_object.date_last_connected = [datetime]::FromFileTime($([System.BitConverter]::ToInt64($(Get-ItemProperty -ErrorAction Ignore $temp)."DateLastConnected", 0)))
			$profiles = $profiles + $profile_object
			#(Get-ItemProperty -ErrorAction Ignore -Path $temp  -ErrorAction SilentlyContinue
			$profile_object | Tee-Object -file $out_file -Append
			#Write-Output '' | Tee-Object -file $out_file -Append
		}
	}
	catch
	{
		$_.Exception.Message
	}
}
else
{
	Write-Output 'Registry key for Wireless Access Points does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs'){
	Write-Output 'URLs visited in Internet Explorer' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Get-ItemProperty -ErrorAction Ignore -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs' | Select-Object * -exclude PSPath,
PSParentPath, PSChildName, PSProvider | Tee-Object -file $out_file -Append
}
else{
	Write-Output 'Registry key for URLs visited in Internet Explorer does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces')
{
	Write-Output 'IP Addresses of interfaces' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	try
	{
		$subkeys = Get-ChildItem  -ErrorAction SilentlyContinue  -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces'  | Select-Object Name -ExpandProperty Name
		
		foreach ($subkey in $subkeys)
		{
			$subkey = "Registry::" + $subkey
			$subsubkeys = $null
			$subsubkeys = Get-ChildItem  -ErrorAction SilentlyContinue -Path $subkey | Select-Object Name -ExpandProperty Name
			#if a key has children, will go in if condition otherwise else will be executed
			if ($subsubkeys -ne $null)
			{
				foreach ($subsubkey in $subsubkeys)
				{
					$temp = 'Registry::' + $subsubkey
					$interface_object = New-Object network_interfaces
					$interface_object.dhcp_default_gateway = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpDefaultGateway"
					if ($interface_object.dhcp_default_gateway -ne '')
					{
						$temp | Tee-Object -file $out_file -Append
						$interface_object.dhcp_domain = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpDomain"
						$interface_object.dhcp_ip_address = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpIpAddress"
						$interface_object.dhcp_subnet_mask = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpSubnetMask"
						$interface_object | Tee-Object -file $out_file -Append
						$interfaces = $interfaces + $interface_object
					}
				}
			}
			else
			{
				$temp = 'Registry::' + $subkey
				$interface_object = New-Object network_interfaces
				$interface_object.dhcp_default_gateway = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpDefaultGateway"
				if ($interface_object.dhcp_default_gateway -ne '')
				{
					$subkey | Tee-Object -file $out_file -Append
					$interface_object.dhcp_domain = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpDomain"
					$interface_object.dhcp_ip_address = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpIpAddress"
					$interface_object.dhcp_subnet_mask = (Get-ItemProperty -ErrorAction Ignore $temp)."DhcpSubnetMask"
					$interface_object | Tee-Object -file $out_file -Append
					$interfaces = $interfaces + $interface_object
				}
			}
		}
	}
	catch
	{
		$_.Exception.Message
	}
}
else {
	Write-Output 'Registry key for IP Addresses for interfaces does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
}

#I did not have this registry key so just trying to print the values available. Change it according to your machine

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'){
	Write-Output 'Start Up Locations in the Registry' | Tee-Object -file $out_file -Append
	Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run' | Tee-Object -file $out_file -Append
}
else{
	Write-Output 'Registry key for Start Up Locations in the Registry does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

#I did not have this registry key so just trying to print the values available. Change it according to your machine

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'){
	Write-Output 'RunOnce Startup in the Registry' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce' | Tee-Object -file $out_file -Append
}
else{
	Write-Output 'Registry key for RunOnce Startup in the Registry does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

#I did not have this registry key so just trying to print the values available. Change it according to your machine

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WOW'){
	Write-Output 'Start Legacy Applications in the Registry' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WOW' | Tee-Object -file $out_file -Append
}
else{
	Write-Output 'Registry key for Start Legacy Applications in the Registry does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'){
	Write-Output 'Run Programs When a Particular User Logs On in the Registry' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run' | Tee-Object -file $out_file -Append
}
else{
	Write-Output 'Registry key for Run Programs When a Particular User Logs On in the Registry does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\System\MountedDevices'){
	Write-Output 'Mounted Devices' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	$all_values = Get-ItemProperty -ErrorAction Ignore -Path 'Registry::HKEY_LOCAL_MACHINE\System\MountedDevices' | Select-Object * -exclude PSPath,
PSParentPath, PSChildName, PSProvider
	$all_values_intm = $all_values -Split '\r?\n'
	$all_values_split = $all_values_intm -Split ";"
	$all_values_split = $all_values_split | ? {$_ -ne ''}
	$all_values_split[0] = $all_values_split[0].substring(1) #trimming first char
	$all_values_split[$all_values_split.Length -1] = $all_values_split[$all_values_split.Length -1].substring(0, $all_values_split[$all_values_split.Length -1].Length -1)
	
	foreach ($value in $all_values_split)
	{
		$value = $value.substring(0, $value.Length - 14)
		$value = $value.substring(1)
		Write-Output "" | Tee-Object -file $out_file -Append
		Write-Output '$value ->' | Tee-Object -file $out_file -Append
		[System.Text.Encoding]::Unicode.GetString((Get-ItemProperty -ErrorAction Ignore -Path "Registry::HKEY_LOCAL_MACHINE\System\MountedDevices").$value) | Tee-Object -file $out_file -Append
		Write-Output '' | Tee-Object -file $out_file -Append
	}
	
}
else{
	Write-Output 'Registry key for Mounted Devices does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
Write-Output '' | Tee-Object -file $out_file -Append

if (Test-Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'){
	Write-Output 'Most recent documents used or opened on the system by file extension' | Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
	$subkeys = Get-ChildItem -ErrorAction Ignore -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' |  Select-Object Name -ExpandProperty Name
	foreach ($subkey in $subkeys)
	{
		Write-Output '-------------------------------------------------------------------------------------------------' | Tee-Object -file $out_file -Append
		Write-Output '' | Tee-Object -file $out_file -Append
		$filename = $subkey.Substring($subkey.LastIndexOf("\") + 1)
		Write-Output "Fetching data for file type $filename" | Tee-Object -file $out_file -Append
		Write-Output '' | Tee-Object -file $out_file -Append
		$subkey = "Registry::" + $subkey | Tee-Object -file $out_file -Append
		Write-Output '' | Tee-Object -file $out_file -Append
		$subkey_value = Get-ItemProperty -ErrorAction Ignore -Path $subkey | Select-Object * -ExcludeProperty MRUListEx, PSPath, PSParentPath, PSChildName, PSProvider
		$subkey_split = $subkey_value -Split '\r?\n' -Split ';'
		$subkey_split[0] = $subkey_split[0].substring(1) #trimming first char
		#removing last character of last item
		$subkey_split[$subkey_split.Length -1] = $subkey_split[$subkey_split.Length -1].substring(0, $subkey_split[$subkey_split.Length -1].Length -1) 
		foreach ($value in $subkey_split)
		{
			$value = $value.substring(0, $value.Length - 14)
			$value = $value.substring(1)
			[String]$output = [System.Text.Encoding]::Unicode.GetString((Get-ItemProperty -ErrorAction Ignore -Path $subkey).$value)
			if ($filename -ne "Folder")
			{
				#using file extension for substring
				#taking substring from 0 to actual file name, cutting the crap out
				$out = $output.Substring(0, ($output.IndexOf(".") + $filename.Length))
			}
			else
			{
				#removing the english letters, numbers and special characters only
				#make necessary changes in the regex as required
				$temp = $output -replace '[^a-zA-Z0-9\s!@#%&*\(\)\[\]-_+=.,:;\{\}?$]', '\'
				$out = $temp.Substring(0, $temp.IndexOf('\'))
			}
			$out | Tee-Object -file $out_file -Append
			Write-Output '' | Tee-Object -file $out_file -Append
		}
	}
}
else {
	Write-Output 'Registry key for Most recent documents does not exist'| Tee-Object -file $out_file -Append
	Write-Output '' | Tee-Object -file $out_file -Append
}

Start-Process notepad.exe $out_file
