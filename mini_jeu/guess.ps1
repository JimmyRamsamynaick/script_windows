<#
    Nombre Mystère
    Devinez un nombre entre 1 et 100.
#>

$target=Get-Random -Minimum 1 -Maximum 101
$tries=0
Write-Host 'Devinez le nombre (1..100). Tapez q pour quitter.' -ForegroundColor Cyan
while($true){
    $input=Read-Host 'Votre essai'
    if($input -eq 'q'){ break }
    if(-not [int]::TryParse($input,[ref]$null)){ Write-Host 'Entrez un nombre.' -ForegroundColor Yellow; continue }
    $n=[int]$input; $tries++
    if($n -lt $target){ Write-Host 'Trop petit.' -ForegroundColor Magenta }
    elseif($n -gt $target){ Write-Host 'Trop grand.' -ForegroundColor Magenta }
    else { Write-Host "Bravo! Trouvé en $tries essais." -ForegroundColor Green; break }
}