<#
    Space Invader (Console Game)

    Contrôles:
    - Flèche gauche/droite: déplacer le vaisseau
    - Espace: tirer
    - Q: quitter

    Exécution:
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\space_invader\game.ps1
#>

$ErrorActionPreference = 'Stop'

[Console]::CursorVisible = $false
$width = 50
$height = 22
$borderChar = '#'

function New-Grid {
    param([int]$w, [int]$h)
    $grid = New-Object 'char[][]' $h
    for ($y=0; $y -lt $h; $y++) {
        $row = New-Object 'char[]' $w
        for ($x=0; $x -lt $w; $x++) { $row[$x] = ' ' }
        $grid[$y] = $row
    }
    return $grid
}

function Draw-Grid {
    param([char[][]]$grid)
    $sb = New-Object System.Text.StringBuilder
    for ($y=0; $y -lt $grid.Length; $y++) {
        [void]$sb.Append([string]::new($grid[$y]))
        [void]$sb.Append([Environment]::NewLine)
    }
    Clear-Host
    Write-Host $sb.ToString()
}

function Draw-Borders {
    param([char[][]]$grid)
    for ($x=0; $x -lt $grid[0].Length; $x++) { $grid[0][$x] = $borderChar; $grid[$grid.Length-1][$x] = $borderChar }
    for ($y=0; $y -lt $grid.Length; $y++) { $grid[$y][0] = $borderChar; $grid[$y][$grid[0].Length-1] = $borderChar }
}

# Entities
$player = @{ X = [int]($width/2); Y = $height-2; Char='A'; Alive=$true }
$aliens = @()
$rows = 4; $cols = 9
for ($ry=0; $ry -lt $rows; $ry++) {
    for ($cx=0; $cx -lt $cols; $cx++) {
        $aliens += @{ X = 4 + ($cx*5); Y = 2 + ($ry*2); Char='M'; Alive=$true }
    }
}
$alienDir = 1
$alienStepCounter = 0

$shots = New-Object System.Collections.Generic.List[object]
$enemyShots = New-Object System.Collections.Generic.List[object]

$score = 0
$tickMs = 60
$lastShotTick = 0
$maxPlayerShots = 1

try {
    while ($true) {
        $grid = New-Grid -w $width -h $height
        Draw-Borders -grid $grid

        # Input
        while ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            switch ($key.Key) {
                'LeftArrow'  { if ($player.X -gt 1) { $player.X-- } }
                'RightArrow' { if ($player.X -lt ($width-2)) { $player.X++ } }
                'Spacebar'   {
                    if ((Get-Date).Ticks - $lastShotTick -gt 2000000 -and $shots.Count -lt $maxPlayerShots) {
                        $shots.Add(@{ X=$player.X; Y=$player.Y-1; Char='|'; Alive=$true })
                        $lastShotTick = (Get-Date).Ticks
                    }
                }
                'Q' { break }
            }
        }

        # Move aliens
        $edgeHit = $false
        foreach ($a in $aliens) {
            if (-not $a.Alive) { continue }
            $a.X += $alienDir
            if ($a.X -le 1 -or $a.X -ge ($width-2)) { $edgeHit = $true }
        }
        $alienStepCounter++
        if ($edgeHit) {
            $alienDir *= -1
            foreach ($a in $aliens) { if ($a.Alive) { $a.Y++ } }
        }

        # Random enemy shots
        if ((Get-Random -Minimum 0 -Maximum 100) -lt 6) {
            $shooters = $aliens | Where-Object { $_.Alive }
            if ($shooters.Count -gt 0) {
                $s = $shooters[(Get-Random -Minimum 0 -Maximum $shooters.Count)]
                $enemyShots.Add(@{ X=$s.X; Y=$s.Y+1; Char='v'; Alive=$true })
            }
        }

        # Move shots
        for ($i=$shots.Count-1; $i -ge 0; $i--) {
            $s = $shots[$i]
            $s.Y--
            if ($s.Y -le 1) { $shots.RemoveAt($i); continue }
            # Collision with alien
            foreach ($a in $aliens) {
                if ($a.Alive -and $a.X -eq $s.X -and $a.Y -eq $s.Y) {
                    $a.Alive = $false; $shots.RemoveAt($i); $score += 10; break
                }
            }
        }

        for ($i=$enemyShots.Count-1; $i -ge 0; $i--) {
            $e = $enemyShots[$i]
            $e.Y++
            if ($e.Y -ge ($height-1)) { $enemyShots.RemoveAt($i); continue }
            # Collision with player
            if ($player.X -eq $e.X -and $player.Y -eq $e.Y) {
                $player.Alive = $false; $enemyShots.RemoveAt($i); break
            }
        }

        # Game over if aliens reach player row
        foreach ($a in $aliens) {
            if ($a.Alive -and $a.Y -ge ($player.Y)) { $player.Alive = $false; break }
        }

        # Draw entities
        if ($player.Alive) { $grid[$player.Y][$player.X] = $player.Char }
        foreach ($a in $aliens) { if ($a.Alive) { $grid[$a.Y][$a.X] = $a.Char } }
        foreach ($s in $shots) { if ($s.Alive) { $grid[$s.Y][$s.X] = $s.Char } }
        foreach ($e in $enemyShots) { if ($e.Alive) { $grid[$e.Y][$e.X] = $e.Char } }

        # HUD
        $hud = " SCORE: $score  (Q pour quitter)"
        $hudChars = $hud.ToCharArray()
        for ($i=0; $i -lt [Math]::Min($hudChars.Length, $width-2); $i++) {
            $grid[0][1+$i] = $hudChars[$i]
        }

        Draw-Grid -grid $grid

        if (-not $player.Alive) {
            Write-Host "\nGAME OVER — Score: $score" -ForegroundColor Red
            Write-Host "Appuyez sur Entrée pour revenir au menu" -ForegroundColor Yellow
            [Console]::ReadLine() | Out-Null
            break
        }

        Start-Sleep -Milliseconds $tickMs
    }
}
catch {
    Write-Host "Erreur: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    [Console]::CursorVisible = $true
}