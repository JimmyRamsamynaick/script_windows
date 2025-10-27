<#
    Snake (Console)
    Contrôles: Flèches pour diriger, Q pour quitter.
#>

$ErrorActionPreference='Stop'
[Console]::CursorVisible=$false

$width=40; $height=18
$dir='Right'
$snake=@([PSCustomObject]@{X=5;Y=5},[PSCustomObject]@{X=4;Y=5},[PSCustomObject]@{X=3;Y=5})
$food=[PSCustomObject]@{X=(Get-Random -Minimum 1 -Maximum ($width-2));Y=(Get-Random -Minimum 2 -Maximum ($height-2))}
$score=0

function Draw-Frame{
    Clear-Host
    Write-Host ('╔' + ('═' * $width) + '╗')
    for($y=0;$y -lt $height;$y++){
        $line='║' + (' ' * $width) + '║'
        $chars=$line.ToCharArray()
        foreach($seg in $snake){ $idx=$seg.X+1; if($idx -lt $chars.Length){ $chars[$idx]='█' } }
        $chars[$food.X+1]='■'
        Write-Host ([string]::new($chars))
    }
    Write-Host ('╚' + ('═' * $width) + '╝')
    Write-Host "Score: $score" -ForegroundColor Cyan
}

function Read-Input{
    if([Console]::KeyAvailable){
        $key=[Console]::ReadKey($true).Key
        switch($key){
            'LeftArrow'  { if($dir -ne 'Right'){ $dir='Left' } }
            'RightArrow' { if($dir -ne 'Left'){ $dir='Right' } }
            'UpArrow'    { if($dir -ne 'Down'){ $dir='Up' } }
            'DownArrow'  { if($dir -ne 'Up'){ $dir='Down' } }
            'Q'          { throw 'Quit' }
        }
    }
}

function Step{
    $head=$snake[0].PSObject.Copy()
    switch($dir){
        'Left'  { $head.X-- }
        'Right' { $head.X++ }
        'Up'    { $head.Y-- }
        'Down'  { $head.Y++ }
    }
    # collisions mur
    if($head.X -lt 0 -or $head.X -ge $width -or $head.Y -lt 0 -or $head.Y -ge $height){ throw 'GameOver' }
    # collisions corps
    foreach($seg in $snake){ if($seg.X -eq $head.X -and $seg.Y -eq $head.Y){ throw 'GameOver' } }
    # nourriture
    $snake = ,$head + $snake
    if($head.X -eq $food.X -and $head.Y -eq $food.Y){
        $score+=10
        $food=[PSCustomObject]@{X=(Get-Random -Minimum 1 -Maximum ($width-2));Y=(Get-Random -Minimum 2 -Maximum ($height-2))}
    }else{
        $snake=$snake[0..($snake.Count-2)]
    }
    return $snake
}

try{
    while($true){
        Read-Input
        $snake=Step
        Draw-Frame
        Start-Sleep -Milliseconds 120
    }
}catch{
    [Console]::CursorVisible=$true
    if($_.Exception.Message -eq 'Quit'){ return }
    Write-Host "Game Over! Score: $score" -ForegroundColor Red
    Read-Host 'Appuyez sur Entrée pour revenir'
}