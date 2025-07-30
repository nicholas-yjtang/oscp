function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName 
    $LDAP = "LDAP://$PDC/$DN"
    $direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry, $LDAPQuery)
    return $dirsearcher.FindAll()
}