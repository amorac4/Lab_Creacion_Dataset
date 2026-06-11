param(
  [Parameter(Mandatory = $true)]
  [string]$Lista,

  [Parameter(Mandatory = $true)]
  [string]$CarpetaObjetivo,

  [string]$Salida = "",

  [switch]$AceptarParciales
)

$ErrorActionPreference = "Stop"
$hashPattern = "(?<![a-fA-F0-9])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![a-fA-F0-9])"

function Get-HashesFromFile {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "No existe el archivo de lista: $Path"
  }

  $seen = @{}
  $content = Get-Content -LiteralPath $Path -Raw
  foreach ($match in [regex]::Matches($content, $hashPattern)) {
    $hash = $match.Value.ToLowerInvariant()
    if (-not $seen.ContainsKey($hash)) {
      $seen[$hash] = $true
      $hash
    }
  }
}

function Test-HasAnyPng {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    return $false
  }

  $png = Get-ChildItem -LiteralPath $Path -Recurse -File -Filter "*.png" -ErrorAction SilentlyContinue |
    Select-Object -First 1
  return $null -ne $png
}

function Test-CompletedSample {
  param(
    [string]$BatchPath,
    [string]$Hash
  )

  $samplePath = Join-Path $BatchPath $Hash
  if (-not (Test-Path -LiteralPath $samplePath -PathType Container)) {
    return $false
  }

  $metadataPath = Join-Path $samplePath "metadata.json"
  if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
    try {
      $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
      $imageCount = 0
      if ($null -ne $metadata.image_count) {
        $imageCount = [int]$metadata.image_count
      }
      if ($metadata.status -eq "completed" -and $imageCount -gt 0) {
        return $true
      }
    } catch {
      # Si metadata esta corrupto o incompleto, usamos la validacion por artefactos.
    }
  }

  $imagesPath = Join-Path $samplePath "images"
  $staticAnalysisPath = Join-Path $samplePath "analysis\static_analysis.json"
  $imageAnalysisPath = Join-Path $samplePath "analysis\image_analysis.json"

  if ($AceptarParciales) {
    return (Test-HasAnyPng -Path $imagesPath)
  }

  return (
    (Test-HasAnyPng -Path $imagesPath) -and
    (Test-Path -LiteralPath $staticAnalysisPath -PathType Leaf) -and
    (Test-Path -LiteralPath $imageAnalysisPath -PathType Leaf)
  )
}

if (-not (Test-Path -LiteralPath $CarpetaObjetivo -PathType Container)) {
  throw "No existe la carpeta objetivo: $CarpetaObjetivo"
}

$hashes = @(Get-HashesFromFile -Path $Lista)
$restantes = New-Object System.Collections.Generic.List[string]
$yaAnalizados = 0

foreach ($hash in $hashes) {
  if (Test-CompletedSample -BatchPath $CarpetaObjetivo -Hash $hash) {
    $yaAnalizados += 1
  } else {
    $restantes.Add($hash)
  }
}

if ($Salida) {
  $salidaDir = Split-Path -Parent $Salida
  if ($salidaDir -and -not (Test-Path -LiteralPath $salidaDir -PathType Container)) {
    New-Item -ItemType Directory -Path $salidaDir | Out-Null
  }
  $restantes | Set-Content -LiteralPath $Salida -Encoding UTF8
}

Write-Host ("Total en lista: {0}. Ya analizados: {1}. Restantes: {2}." -f $hashes.Count, $yaAnalizados, $restantes.Count)
$restantes
