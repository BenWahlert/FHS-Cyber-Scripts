# --------------------------------------------------------------------------------------
#       Title: CIS-CAT File Powershell Cmdlets
# Description: The functions contained in this script are utilized by the File
#              probes within the CIS-CAT software.
#
# Author            Modification Date          Description of Modification(s)
# --------------------------------------------------------------------------------------
# Bill Munyan       October 27, 2014           Original Author
# --------------------------------------------------------------------------------------

#
# (Done) Collect Application Host configurations
#
Function Get-FileInformation {
    param(
        [Parameter(ValueFromPipeline=$true)][String]$Path=$(throw "Mandatory parameter -Path missing.")
    )
	Process {
        # The results
        $FI = New-Object PSObject

        $name = Get-Item $Path -ErrorAction SilentlyContinue | Select-Object Name
        if ($name) {
            $owner = Get-ACL -Path $Path | Select-Object Owner
            $length = Get-Item $Path | Select-Object Length

            $atime  = (Get-ItemProperty -Path $Path -Name LastAccessTime).LastAccessTime.ToFileTime()
            $ctime  = (Get-ItemProperty -Path $Path -Name CreationTime).CreationTime.ToFileTime()
            $mtime  = (Get-ItemProperty -Path $Path -Name LastWriteTime).LastWriteTime.ToFileTime()
            $isFile = (Get-Item $Path) -is [System.IO.FileInfo]
        
            # Directories don't have this information.
            if ($isFile) {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path) | 
                    Select-Object FileVersionRaw, FileVersion, CompanyName, InternalName, Language, OriginalFilename, ProductName, ProductVersionRaw, ProductVersion
            }

            $fv = $versionInfo.FileVersion
            if ($fv) {
                # Calculate development_class
                $p = $fv.IndexOf("(")
                if ($p -ge 0) {
                    $vp = $fv.IndexOf(".", $p)
                    if ($vp -ge 0) {
                        $dc = $fv.Substring(($p+1), (($vp-$p)-1))
                    }
                } else {
                    $dc = "[[DOES NOT EXIST]]"
                }

                # Set the version info field values.
                if ($versionInfo.FileVersionRaw) {
                    $actualVersion = $versionInfo.FileVersionRaw
                } else {
                    $actualVersion = $versionInfo.ProductVersion
                }
                $actualCompanyName      = $versionInfo.CompanyName
                $actualInternalName     = $versionInfo.InternalName
                $actualLanguage         = $versionInfo.Language
                $actualOriginalFilename = $versionInfo.OriginalFilename
                $actualProductName      = $versionInfo.ProductName
                $actualProductVersion   = $versionInfo.ProductVersionRaw
            } else {
                # There was no version info; Set all the field values to DNE
                $actualVersion          = "[[DOES NOT EXIST]]"
                $actualCompanyName      = "[[DOES NOT EXIST]]"
                $actualInternalName     = "[[DOES NOT EXIST]]"
                $actualLanguage         = "[[DOES NOT EXIST]]"
                $actualOriginalFilename = "[[DOES NOT EXIST]]"
                $actualProductName      = "[[DOES NOT EXIST]]"
                $actualProductVersion   = "[[DOES NOT EXIST]]"

                $dc = "[[DOES NOT EXIST]]"
            }

            # Add the required properties
            $FI | Add-Member Noteproperty exists -Value $true
            $FI | Add-Member Noteproperty owner -Value $owner.Owner
            $FI | Add-Member Noteproperty size -Value $length.Length
            $FI | Add-Member Noteproperty a_time -Value $atime
            $FI | Add-Member Noteproperty c_time -Value $ctime
            $FI | Add-Member Noteproperty m_time -Value $mtime

            if ($isFile) {
                $FI | Add-Member Noteproperty version -Value $actualVersion
                $FI | Add-Member Noteproperty company -Value $actualCompanyName
                $FI | Add-Member Noteproperty internal_name -Value $actualInternalName
                $FI | Add-Member Noteproperty language -Value $actualLanguage
                $FI | Add-Member Noteproperty original_filename -Value $actualOriginalFilename
                $FI | Add-Member Noteproperty product_name -Value $actualProductName
                $FI | Add-Member Noteproperty product_version -Value $actualProductVersion
                $FI | Add-Member Noteproperty development_class -Value $dc
            } else {
                #
                # The UNKNOWN marker for the following values marks the elements in the
                # system characteristics to a status of "not collected" for directories
                #
                $FI | Add-Member Noteproperty version -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty company -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty internal_name -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty language -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty original_filename -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty product_name -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty product_version -Value "[[UNKNOWN]]"
                $FI | Add-Member Noteproperty development_class -Value "[[UNKNOWN]]"
            }
        } else {
            $FI | Add-Member Noteproperty exists -Value $false
            $FI | Add-Member Noteproperty owner -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty size -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty a_time -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty c_time -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty m_time -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty version -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty development_class -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty company -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty internal_name -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty language -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty original_filename -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty product_name -Value "[[DOES NOT EXIST]]"
            $FI | Add-Member Noteproperty product_version -Value "[[DOES NOT EXIST]]"
        }

        # Select the fields we need to create the <file_item>
		$FI | Select-Object exists, owner, size, a_time, c_time, m_time, version, development_class, 
            company, internal_name, language, original_filename, product_name, product_version
    }
}