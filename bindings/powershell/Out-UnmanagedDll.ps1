function Out-UnmanagedDll
{
    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [String]
        $FilePath
    )

    $Path = Resolve-Path $FilePath

    if (! [IO.File]::Exists($Path))
    {
        Throw "$Path does not exist."
    }

    $FileBytes = [System.IO.File]::ReadAllBytes($Path)

    if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')
    {
        Throw "$Path is not a valid executable."
    }

	# Encode
    $Length = $FileBytes.Length
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($FileBytes, 0, $FileBytes.Length)
    $DeflateStream.Dispose()
    $CompressedFileBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedFile = [Convert]::ToBase64String($CompressedFileBytes)

	# Decode
	$Output = @"
`$EncodedCompressedFile = @'
$EncodedCompressedFile
'@
`$Stream = new-object -TypeName System.IO.MemoryStream
`$DeflateStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`$EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
`$buffer = New-Object Byte[]($Length)
`$count = 0
do
    {
        `$count = `$DeflateStream.Read(`$buffer, 0, 1024)
        if (`$count -gt 0)
            {
                `$Stream.Write(`$buffer, 0, `$count)
            }
    }
While (`$count -gt 0)
`$array = `$stream.ToArray()
`$DeflateStream.Close()
`$Stream.Close()
Set-Content -value `$array -encoding byte -path `$DllPath
"@

	Write-Output $Output
}