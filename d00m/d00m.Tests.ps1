$root = Split-path $MyInvocation.MyCommand.Path -Parent

Import-Module $root\d00m.psm1 -Force

Describe "Get-d00mExcuse" {
    It "should not throw" {
        {Get-d00mExcuse} | 
            Should Not Throw
    }

    It "should output 1 phrase when count not specified" {
        (Get-d00mExcuse).Count | 
            Should be 1
    }

    $number = Get-Random -Minimum 1 -Maximum 10 
    It ("should output {0} phrases when {0} specified" -f $number) { 
        (Get-d00mExcuse -Count $number).Count | 
            Should be $number
    }

    It "should output nothing when 0 count specified" {
        (Get-d00mExcuse -Count 0).Count | 
            Should be 0
    }

    It "should output a 3-word string" {
        (Get-d00mExcuse).Split(' ').Count |
            Should be 3
    }
}

<#
Describe "Add-d00mChocolateyPackageSource" {
    $creds = Get-Credential
    Get-PackageSource -Name chocolatey -ErrorAction SilentlyContinue | Unregister-PackageSource
    it "Actually works" {
        Add-d00mChocolateyPackageSource -Trusted -Credential $creds
        {Get-PackageProvider -Name chocolatey -ErrorAction Stop} | 
            Should not throw
    }
}
#>

Describe "New-d00mPassword" {
    $length = Get-Random -Minimum 5 -Maximum 10

    It "Outputs a string by default" {
        New-d00mPassword | 
            Should BeOfType String
    }

    It "Throws when length 0 specified" {
        {New-d00mPassword -Length 0} | 
            Should Throw
    }

    It "Creates $length character password when $length specified" {
        $password = 
        (New-d00mPassword -Length $length).Length | 
            Should Be $length
    }
}


Describe "New-d00mShortcutCheatSheet" {
    It "Does not throw when executed without parameters" {
        {New-d00mShortcutCheatSheet} |
            Should not throw
    }
}


Describe "ConvertTo-d00mEncryptedString" {
    It "Outputs a string" {
        ConvertTo-d00mEncryptedString -StringToEncrypt 'Hello' | 
            Should BeOfType String
    }

    It "Encrypts 'Hello' correctly to 'kAAAAMoAAADYAAAA2AAAAN4AAAA='" {
        ConvertTo-d00mEncryptedString -StringToEncrypt 'Hello' | 
            Should BeExactly 'kAAAAMoAAADYAAAA2AAAAN4AAAA='
    }
}

Describe "ConvertFrom-d00mEncryptedString" {
    It "Outputs a string" {
        ConvertFrom-d00mEncryptedString -StringToDecrypt 'kAAAAMoAAADYAAAA2AAAAN4AAAA=' | 
            Should BeOfType String
    }

    It "Correctly decrypts 'kAAAAMoAAADYAAAA2AAAAN4AAAA=' to 'Hello'" {
        (ConvertFrom-d00mEncryptedString -StringToDecrypt 'kAAAAMoAAADYAAAA2AAAAN4AAAA=') | 
            Should BeExactly 'Hello'
    }
}

Describe "Switch-d00mMouseButton" {
    It "Does not throw when right-to-left" {
        {Switch-d00mMouseButton -Hand Left} |
            Should Not Throw
    }

    It "Does throw when left-to-left" {
        {Switch-d00mMouseButton -Hand Left} |
            Should throw
    }

    It "Does not throw when left-to-right" {
        {Switch-d00mMouseButton -Hand Right} |
            Should Not Throw
    }
}