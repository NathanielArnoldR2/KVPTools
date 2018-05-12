<#
.SYNOPSIS
   Given a Virtual Machine ID, a value Origin, and a Name, retrieves the value
   assigned to a given KVP exchange key, or $null if the key is not found. Any
   failure in querying this data from WMI will throw an exception.
#>
function Get-KvpValue {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [guid]
    $VMId,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("Guest", "GuestIntrinsic", "Host")]
    [String]
    $Origin,

    [Parameter(
      Mandatory = $true
    )]
    [String]
    $Name
  )

  $kvpObject = Get-CimInstance -Namespace root\virtualization\v2 `
                               -ClassName Msvm_ComputerSystem `
                               -Filter "Name='$VMId'" |
                 Get-CimAssociatedInstance -ResultClassName Msvm_KvpExchangeComponent

  if ($kvpObject -eq $null) {
    throw "The KVP store for this VM could not be queried." # Let the calling code determine severity of failure.
  }

  if ($Origin -eq "Guest") {
    $items = $kvpObject.GuestExchangeItems
  }
  elseif ($Origin -eq "GuestIntrinsic") {
    $items = $kvpObject.GuestIntrinsicExchangeItems
  }
  elseif ($Origin -eq "Host") {
    $kvpObject = $kvpObject |
                   Get-CimAssociatedInstance -ResultClassName Msvm_KvpExchangeComponentSettingData

    if ($kvpObject -eq $null) {
      throw "The Host KVP store for this VM could not be queried." # Let the calling code determine severity of failure.
    }

    $items = $kvpObject.HostExchangeItems
  }

  $item = $items |
            ForEach-Object {[xml]$_} |
            ForEach-Object INSTANCE |
            Where-Object {
              $_ |
                ForEach-Object PROPERTY |
                Where-Object Name -eq Name |
                ForEach-Object Value |
                ForEach-Object Equals $Name
            }

  if ($item -eq $null) {
    return
  }

  $item |
    ForEach-Object PROPERTY |
    Where-Object Name -eq Data |
    ForEach-Object Value
}

<#
.SYNOPSIS
   Given a Virtual Machine ID, a value Origin, a Name, and a desired state of
   existence, returns a boolean value that indicates whether a Key is proven
   to be present or absent, as desired.

   The function wraps Get-KvpValue, and interprets any exceptions thrown as a
   failure to attain the desired proof.
#>
function Test-KvpValue {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [guid]
    $VMId,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("Guest", "GuestIntrinsic", "Host")]
    [String]
    $Origin,

    [Parameter(
      Mandatory = $true
    )]
    [String]
    $Name,

    [Parameter(
      Mandatory = $true
    )]
    [Bool]
    $Exists
  )
  try {
    $value = Get-KvpValue -VMId $VMId -Origin $Origin -Name $Name -ErrorAction Stop
  } catch {
    $Global:Error.RemoveAt(0) # Remove (non)error from register.

    return $false # If the KVP store could not be queried, nothing can be proven.
  }

  $doesExist = $value -ne $null

  return $Exists -eq $doesExist
}

<#
.SYNOPSIS
   Given a Virtual Machine ID, and (optionally) PowerShell Credential objects,
   queries intrinsic KVP data to determine whether the PowerShell direct shim
   is warranted (see below), then tests the provided credentials to determine
   which, if any, are valid for invoking the PowerShell Direct shim.

   If the Shim is found to be needed, yet no suitable credentials have been
   provided, the condition is considered terminal.

   The PowerShell Direct shim is currently required for unpatched Windows 10
   v1607 and Server 2016 RTW.
#>
function Test-KvpPSDirectShim {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [guid]
    $VMId,

    [ValidateCount(1,3)]
    [pscredential[]]
    $Credentials
  )

  $outObj = [PSCustomObject]@{
    IsNeeded = $null
    Credential = $null
  }

  do {
    try {
      $OSVersion = (
        Get-KvpValue -VMId $VMId -Origin GuestIntrinsic -Name OSVersion -ErrorAction Stop
      ) -as [version]
    } catch {
      $Global:Error.RemoveAt(0)

      Start-Sleep -Seconds 60
    }
  } until ($OSVersion -is [version])

  $shimVersions = @(
    "10.0.14393" |
      ForEach-Object {[version]$_}
  )

  if ($OSVersion -notin $shimVersions) {
    $outObj.IsNeeded = $false
    return $outObj
  }

  Write-Verbose "  - Using PowerShell Direct shim."

  $outObj.IsNeeded = $true

  $shout = {"The mountains are singing, and the Lady comes."}

  $inc = 1
  do {
    foreach ($cred in $Credentials) {
      $echo = Invoke-Command -VMId $VMId `
                             -ScriptBlock $shout `
                             -Credential $cred `
                             -ErrorAction Ignore

      if ($echo -eq $shout.Invoke()) {
        $outObj.Credential = $cred
        break
      }
    }

    $inc++
  } while ($outObj.Credential -eq $null -and $inc -le 5)

  if ($outObj.Credential -eq $null) {
    throw "Unable to select a working credential for PowerShell Direct."
  }

  return $outObj
}

<#
.SYNOPSIS
   Given a Virtual Machine ID, a PowerShell credential object, and the name of
   a KVP item that exists among the host values, utilizes PowerShell Direct to
   enforce deletion of that item, thereby allowing the guest component of a
   handshake to proceed.
#>
function Invoke-KvpPSDirectShim {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [guid]
    $VMId,

    [Parameter(
      Mandatory = $true
    )]
    [pscredential]
    $Credential,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ValueName
  )

  $scriptBlock = {
    param ($ValueName)

    $path = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\External"

    $properties = Get-Item -LiteralPath $path |
                    ForEach-Object Property

    if ($properties -notcontains $ValueName) {
      return $true
    }

    Remove-ItemProperty -LiteralPath $path -Name $ValueName
  }

  do {
    $response = Invoke-Command -VMId $VMId `
                               -Credential $Credential `
                               -ScriptBlock $scriptBlock `
                               -ArgumentList $ValueName `
                               -ErrorAction Ignore
  } while ($response -ne $true)
}

<#
.SYNOPSIS
   Handles the host component of a "handshake" between host and guest in which
   the guest asserts completion of configuration, or of a portion thereof, and
   the host acknowledges this assertion.
#>
function Start-KvpFinAckHandshake {
  [CmdletBinding(
    DefaultParameterSetName = "NoShim",
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [guid]
    $VMId,

    [Parameter(
      ParameterSetName = "UseShim",
      Mandatory = $true
    )]
    [switch]
    $UseShim,

    [Parameter(
      ParameterSetName = "UseShim",
      Mandatory = $true
    )]
    [pscredential[]]
    $Credentials
  )

  # Wait for FIN.
  while ($true) {
    if (Test-KvpValue -VMId $VMId -Origin Guest -Name fin -Exists $true) {
      break
    }

    if (Test-KvpValue -VMId $VMId -Origin Guest -Name err -Exists $true) {
      throw "The vm has written an 'err' assertion to its host-visible kvp values, indicating an error was logged before invoking the fin-ack handshake."
    }

    Start-Sleep -Seconds 60
  }

  # Write ACK.
  $vmmsObj = Get-WmiObject -Namespace root\virtualization\v2 `
                           -Class Msvm_VirtualSystemManagementService

  $vmObj = Get-WmiObject -Namespace root\virtualization\v2 `
                         -ClassName Msvm_ComputerSystem `
                         -Filter "Name='$VMId'"

  $ackObj = ([WMIClass]"\\$(hostname)\root\virtualization\v2:Msvm_KvpExchangeDataItem").CreateInstance()
  $ackObj.Name = "ack"
  $ackObj.Data = ""
  $ackObj.Source = 0

  $vmmsObj.AddKvpItems($vmObj, $ackObj.PSBase.GetText("CimDtd20")) | Out-Null

  while (-not (Test-KvpValue -VMId $VMId -Origin Host -Name ack -Exists $true)) {
    Start-Sleep -Seconds 5
  }

  # Wait for FIN Withdrawal.
  while (-not (Test-KvpValue -VMId $VMId -Origin Guest -Name fin -Exists $false)) {
    Start-Sleep -Seconds 5
  }

  if ($PSCmdlet.ParameterSetName -eq "UseShim") {
    $shim = Test-KvpPSDirectShim -VMId $VMId -Credentials $Credentials
  }
  else {
    $shim = $null
  }

  # Withdraw ACK.
  $vmmsObj.RemoveKvpItems($vmObj, $ackObj.PSBase.GetText("CimDtd20")) | Out-Null
  while (-not (Test-KvpValue -VMId $VMId -Origin Host -Name ack -Exists $false)) {
    Start-Sleep -Seconds 5
  }

  # Confirm withdrawal of ACK using shim.
  if ($shim -and $shim.IsNeeded) {
    Invoke-KvpPSDirectShim -VMId $VMId -Credential $shim.Credential -ValueName ack
  }
}

<#
.SYNOPSIS
   Handles the host component of a "handshake" between host and guest in which
   the host signals to the guest readiness for guest configuration to proceed,
   and the guest acknowledges receipt of this signal.
#>
function Start-KvpPokeAckHandshake {
  [CmdletBinding(
    DefaultParameterSetName = "NoShim",
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [guid]
    $VMId,

    [Parameter(
      ParameterSetName = "UseShim",
      Mandatory = $true
    )]
    [switch]
    $UseShim,

    [Parameter(
      ParameterSetName = "UseShim",
      Mandatory = $true
    )]
    [pscredential[]]
    $Credentials
  )

  # Write POKE
  $vmmsObj = Get-WmiObject -Namespace root\virtualization\v2 `
                           -Class Msvm_VirtualSystemManagementService

  $vmObj = Get-WmiObject -Namespace root\virtualization\v2 `
                         -ClassName Msvm_ComputerSystem `
                         -Filter "Name='$VMId'"

  $pokeObj = ([WMIClass]"\\$(hostname)\root\virtualization\v2:Msvm_KvpExchangeDataItem").CreateInstance()
  $pokeObj.Name = "poke"
  $pokeObj.Data = ""
  $pokeObj.Source = 0

  $vmmsObj.AddKvpItems($vmObj, $pokeObj.PSBase.GetText("CimDtd20")) | Out-Null

  while (-not (Test-KvpValue -VMId $VMId -Origin Host -Name poke -Exists $true)) {
    Start-Sleep -Seconds 5
  }

  # Wait for ACK.
  while (-not (Test-KvpValue -VMId $VMId -Origin Guest -Name ack -Exists $true)) {
    Start-Sleep -Seconds 60
  }

  if ($PSCmdlet.ParameterSetName -eq "UseShim") {
    $shim = Test-KvpPSDirectShim -VMId $VMId -Credentials $Credentials
  }
  else {
    $shim = $null
  }

  # Withdraw POKE.
  $vmmsObj.RemoveKvpItems($vmObj, $pokeObj.PSBase.GetText("CimDtd20")) | Out-Null

  while (-not (Test-KvpValue -VMId $VMId -Origin Host -Name poke -Exists $false)) {
    Start-Sleep -Seconds 5
  }

  # Confirm withdrawal of POKE using shim.
  if ($shim -and $shim.IsNeeded) {
    Invoke-KvpPSDirectShim -VMId $VMId -Credential $shim.Credential -ValueName poke
  }

  # Wait for ACK withdrawal
  while (-not (Test-KvpValue -VMId $VMId -Origin Guest -Name ack -Exists $false)) {
    Start-Sleep -Seconds 5
  }
}

Export-ModuleMember -Function Start-KvpFinAckHandshake,
                              Start-KvpPokeAckHandshake