# Recoverable Discord cache reset adapted from Flowseal service.bat diagnostics.
# Run from PowerShell as the affected Windows user. Administrator rights are
# not required. Cache folders are renamed, not deleted.

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$variants = @(
    @{ Process = "Discord";            Name = "Discord";             Root = Join-Path $env:APPDATA "discord" },
    @{ Process = "DiscordPTB";         Name = "Discord PTB";         Root = Join-Path $env:APPDATA "discordptb" },
    @{ Process = "DiscordCanary";      Name = "Discord Canary";      Root = Join-Path $env:APPDATA "discordcanary" },
    @{ Process = "DiscordDevelopment"; Name = "Discord Development"; Root = Join-Path $env:APPDATA "discorddevelopment" }
)

$installed = @($variants | Where-Object { Test-Path -LiteralPath $_.Root })
if ($installed.Count -eq 0) {
    Write-Host "Установки Discord в APPDATA не найдены." -ForegroundColor Yellow
    exit 0
}

Write-Host "Будут закрыты найденные процессы Discord." -ForegroundColor Yellow
Write-Host "Cache, Code Cache и GPUCache будут переименованы с суффиксом .xkeen-backup-$stamp."
$answer = Read-Host "Продолжить? [y/N]"
if ($answer -notmatch '^(?i:y|yes|д|да)$') {
    Write-Host "Отменено."
    exit 0
}

foreach ($variant in $installed) {
    $variantRoot = Get-Item -LiteralPath $variant.Root
    if ($variantRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Отказ: каталог Discord является ссылкой: $($variant.Root)"
    }
    Get-Process -Name $variant.Process -ErrorAction SilentlyContinue | Stop-Process -Force
    foreach ($cacheName in @("Cache", "Code Cache", "GPUCache")) {
        $source = Join-Path $variant.Root $cacheName
        if (-not (Test-Path -LiteralPath $source)) { continue }
        $cacheItem = Get-Item -LiteralPath $source
        if ($cacheItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Отказ: cache-каталог является ссылкой: $source"
        }
        $target = Join-Path $variant.Root ($cacheName + ".xkeen-backup-" + $stamp)
        Rename-Item -LiteralPath $source -NewName (Split-Path $target -Leaf)
        Write-Host ("{0}: {1} -> {2}" -f $variant.Name, $source, $target) -ForegroundColor Green
    }
}

Write-Host "Готово. Запустите Discord снова." -ForegroundColor Green
Write-Host "Если потребуется откат, закройте Discord, удалите новый cache-каталог и верните исходное имя папке .xkeen-backup-$stamp."
