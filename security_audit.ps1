<#
.SYNOPSIS
    Windows Security Auditor — auditoria completa de segurança Windows.
    Verifica configurações, contas, serviços, firewall, Defender e patches.
    Gera relatório HTML com score e findings categorizados.
.NOTES
    Execute como Administrador para dados completos.
#>

#Requires -Version 5.1
$ErrorActionPreference = 'SilentlyContinue'

$hostname  = $env:COMPUTERNAME
$ts        = Get-Date -Format 'yyyyMMdd_HHmmss'
$geradoEm  = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
$saida     = Join-Path $PSScriptRoot "audit_output"
if (-not (Test-Path $saida)) { New-Item -ItemType Directory -Path $saida | Out-Null }

$findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$score     = 100

function Add-Finding($sev, $cat, $titulo, $detalhe, $pontos) {
    $script:findings.Add([PSCustomObject]@{
        Severidade = $sev; Categoria = $cat
        Titulo = $titulo; Detalhe = $detalhe
    })
    $script:score -= $pontos
}

Write-Host "`n  WINDOWS SECURITY AUDITOR" -ForegroundColor Cyan
Write-Host "  Host: $hostname | $geradoEm`n"

# ── 1. Política de senhas ──────────────────────────────────────────────────────
Write-Host "  [1/9] Política de senhas..." -ForegroundColor Gray
$passPolicy = net accounts 2>$null
if ($passPolicy -match 'Minimum password length:\s+(\d+)') {
    if ([int]$Matches[1] -lt 12) { Add-Finding 'High' 'Senhas' 'Comprimento mínimo de senha insuficiente' "Mínimo atual: $($Matches[1]) caracteres. Recomendado: 12+" 10 }
}
if ($passPolicy -match 'Maximum password age \(days\):\s+(\w+)') {
    $age = $Matches[1]
    if ($age -eq 'Unlimited' -or [int]$age -gt 90) { Add-Finding 'Medium' 'Senhas' 'Expiração de senha muito longa ou desativada' "Valor atual: $age dias. Recomendado: máximo 90 dias" 7 }
}

# ── 2. Contas locais ───────────────────────────────────────────────────────────
Write-Host "  [2/9] Contas locais..." -ForegroundColor Gray
Get-LocalUser | ForEach-Object {
    if ($_.Enabled -and -not $_.PasswordRequired) {
        Add-Finding 'Critical' 'Contas' "Conta sem senha: $($_.Name)" "A conta '$($_.Name)' está habilitada sem senha definida" 20
    }
    if ($_.Name -eq 'Guest' -and $_.Enabled) {
        Add-Finding 'High' 'Contas' 'Conta Guest habilitada' "A conta Guest está habilitada e representa risco de segurança" 10
    }
    if ($_.Name -eq 'Administrator' -and $_.Enabled) {
        Add-Finding 'Medium' 'Contas' 'Conta Administrator padrão habilitada' "Considere renomear ou desabilitar a conta Administrator padrão" 5
    }
    if ($_.Enabled -and $_.PasswordExpires -eq $null) {
        Add-Finding 'Medium' 'Contas' "Senha sem expiração: $($_.Name)" "A conta '$($_.Name)' tem senha configurada para nunca expirar" 5
    }
}

# ── 3. RDP ────────────────────────────────────────────────────────────────────
Write-Host "  [3/9] Configurações de RDP..." -ForegroundColor Gray
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
if ($rdp.fDenyTSConnections -eq 0) {
    $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
    if ($nla.UserAuthentication -ne 1) {
        Add-Finding 'Critical' 'RDP' 'RDP habilitado sem NLA (Network Level Authentication)' "RDP está ativo mas NLA está desativado — vulnerável a ataques de autenticação" 15
    } else {
        Add-Finding 'Info' 'RDP' 'RDP habilitado com NLA ativo' "RDP está habilitado com Network Level Authentication — configuração adequada" 0
    }
}

# ── 4. Windows Firewall ────────────────────────────────────────────────────────
Write-Host "  [4/9] Windows Firewall..." -ForegroundColor Gray
Get-NetFirewallProfile | ForEach-Object {
    if (-not $_.Enabled) {
        Add-Finding 'Critical' 'Firewall' "Firewall desativado no perfil: $($_.Name)" "O Windows Firewall está desabilitado para o perfil '$($_.Name)'" 15
    }
}

# ── 5. Windows Defender ───────────────────────────────────────────────────────
Write-Host "  [5/9] Windows Defender..." -ForegroundColor Gray
$defender = Get-MpComputerStatus
if ($defender) {
    if (-not $defender.AntivirusEnabled)    { Add-Finding 'Critical' 'Antivirus' 'Windows Defender desativado' "Proteção antivírus em tempo real está desabilitada" 20 }
    if (-not $defender.RealTimeProtectionEnabled) { Add-Finding 'High' 'Antivirus' 'Proteção em tempo real desativada' "RealTimeProtection está desabilitado no Defender" 10 }
    $sigAge = (New-TimeSpan $defender.AntivirusSignatureLastUpdated).TotalDays
    if ($sigAge -gt 3) { Add-Finding 'High' 'Antivirus' "Assinaturas desatualizadas ($([math]::Round($sigAge)) dias)" "As definições do Defender não são atualizadas há $([math]::Round($sigAge,1)) dias" 10 }
}

# ── 6. Atualizações ───────────────────────────────────────────────────────────
Write-Host "  [6/9] Histórico de patches..." -ForegroundColor Gray
$ultimoPatch = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
if ($ultimoPatch) {
    $diasSemPatch = (New-TimeSpan $ultimoPatch).TotalDays
    if ($diasSemPatch -gt 60) { Add-Finding 'High' 'Patches' "Sem patches há $([math]::Round($diasSemPatch)) dias" "Último patch: $($ultimoPatch.ToString('yyyy-MM-dd')). Mantenha o sistema atualizado" 10 }
    elseif ($diasSemPatch -gt 30) { Add-Finding 'Medium' 'Patches' "Patches com $([math]::Round($diasSemPatch)) dias" "Último patch: $($ultimoPatch.ToString('yyyy-MM-dd')).  Recomendado: máximo 30 dias" 5 }
}

# ── 7. Serviços com credenciais ────────────────────────────────────────────────
Write-Host "  [7/9] Serviços com credenciais..." -ForegroundColor Gray
Get-CimInstance Win32_Service | Where-Object {
    $_.StartName -and $_.StartName -notin @('LocalSystem','NT AUTHORITY\LocalService','NT AUTHORITY\NetworkService','LocalService','NetworkService')
} | ForEach-Object {
    Add-Finding 'Medium' 'Serviços' "Serviço com conta específica: $($_.Name)" "Serviço '$($_.DisplayName)' roda como '$($_.StartName)' — verifique privilégios" 3
}

# ── 8. Shares ─────────────────────────────────────────────────────────────────
Write-Host "  [8/9] Compartilhamentos..." -ForegroundColor Gray
Get-SmbShare | Where-Object { $_.Name -notlike '*$' } | ForEach-Object {
    Add-Finding 'Medium' 'Shares' "Share não-administrativo: $($_.Name)" "Caminho: $($_.Path) — Verifique se é necessário e as permissões aplicadas" 4
}

# ── 9. Portas abertas ─────────────────────────────────────────────────────────
Write-Host "  [9/9] Portas abertas..." -ForegroundColor Gray
$portasRisco = @{23='Telnet';21='FTP';139='NetBIOS';137='NetBIOS-NS';5985='WinRM-HTTP'}
Get-NetTCPConnection -State Listen | Where-Object { $portasRisco.ContainsKey($_.LocalPort) } | ForEach-Object {
    Add-Finding 'High' 'Rede' "Porta de risco aberta: $($_.LocalPort) ($($portasRisco[$_.LocalPort]))" "A porta $($_.LocalPort) ($($portasRisco[$_.LocalPort])) está em escuta — considere desabilitar" 8
}

$score = [math]::Max(0, $score)

# ── HTML ──────────────────────────────────────────────────────────────────────
$sevColor = @{ Critical='#ef4444'; High='#f97316'; Medium='#eab308'; Info='#00d4ff' }
$sevBg    = @{ Critical='#7f1d1d'; High='#7c2d12'; Medium='#713f12'; Info='#0c2a4a' }
$scoreColor = if ($score -ge 80) { '#4ade80' } elseif ($score -ge 60) { '#eab308' } else { '#ef4444' }
$grade = if ($score -ge 90) {'A'} elseif ($score -ge 80) {'B'} elseif ($score -ge 70) {'C'} elseif ($score -ge 60) {'D'} else {'F'}

$rows = ($findings | ForEach-Object {
    $sc = $sevColor[$_.Severidade]; $sb = $sevBg[$_.Severidade]
    "<tr><td><span style='background:$sb;color:$sc;padding:2px 8px;border-radius:4px;font-size:.68rem'>$($_.Severidade)</span></td>
    <td>$($_.Categoria)</td><td>$($_.Titulo)</td><td>$($_.Detalhe)</td></tr>"
}) -join ''

$html = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>Security Audit — $hostname</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#020c1b;color:#c9d1d9}
header{background:#0a1628;border-bottom:1px solid #00d4ff22;padding:20px 32px;display:flex;align-items:center;gap:24px}
.score-box{text-align:center;min-width:90px}
.score-num{font-size:2.8rem;font-weight:800;color:$scoreColor;line-height:1}
.score-grade{font-size:1rem;color:$scoreColor;font-weight:700}
.score-label{font-size:.65rem;color:#484f58;text-transform:uppercase;letter-spacing:.1em}
header h1{font-size:1.2rem;color:#fff}header p{color:#484f58;font-size:.82rem;margin-top:4px}
.container{max-width:1200px;margin:0 auto;padding:24px}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.sum-card{background:#0a1628;border:1px solid #ffffff08;border-radius:8px;padding:14px;text-align:center}
.sum-num{font-size:1.8rem;font-weight:700}
.sum-label{font-size:.68rem;color:#484f58;text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.card{background:#0a1628;border:1px solid #ffffff08;border-radius:10px;padding:20px}
.card-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:#00d4ff;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:.76rem}
th{text-align:left;padding:8px 10px;color:#484f58;font-weight:500;border-bottom:1px solid #ffffff08}
td{padding:7px 10px;border-bottom:1px solid #ffffff05;vertical-align:top}
tr:hover td{background:#0d1f35}tr:last-child td{border:none}
footer{text-align:center;padding:16px;color:#484f58;font-size:.72rem}
</style></head><body>
<header>
  <div class="score-box">
    <div class="score-num">$score</div>
    <div class="score-grade">$grade</div>
    <div class="score-label">Score</div>
  </div>
  <div>
    <h1>Windows Security Audit</h1>
    <p>Host: <strong>$hostname</strong> &nbsp;·&nbsp; $geradoEm</p>
  </div>
</header>
<div class="container">
  <div class="summary">
    <div class="sum-card"><div class="sum-num" style="color:#ef4444">$(@($findings|Where-Object Severidade -eq 'Critical').Count)</div><div class="sum-label">Critical</div></div>
    <div class="sum-card"><div class="sum-num" style="color:#f97316">$(@($findings|Where-Object Severidade -eq 'High').Count)</div><div class="sum-label">High</div></div>
    <div class="sum-card"><div class="sum-num" style="color:#eab308">$(@($findings|Where-Object Severidade -eq 'Medium').Count)</div><div class="sum-label">Medium</div></div>
    <div class="sum-card"><div class="sum-num" style="color:#00d4ff">$(@($findings|Where-Object Severidade -eq 'Info').Count)</div><div class="sum-label">Info</div></div>
  </div>
  <div class="card">
    <div class="card-title">Findings ($(@($findings).Count))</div>
    <table><thead><tr><th>Severidade</th><th>Categoria</th><th>Título</th><th>Detalhe</th></tr></thead>
    <tbody>$rows</tbody></table>
  </div>
</div>
<footer>Windows Security Auditor · PowerShell · github.com/Luca-css/windows-security-auditor · $geradoEm</footer>
</body></html>
"@

$htmlPath = Join-Path $saida "audit_${hostname}_${ts}.html"
$html | Out-File $htmlPath -Encoding UTF8

Write-Host "`n  Score: $score/100 (Nota: $grade)" -ForegroundColor $(if($score -ge 80){'Green'}elseif($score -ge 60){'Yellow'}else{'Red'})
Write-Host "  Findings: $(@($findings).Count) ($(@($findings|Where-Object Severidade -eq 'Critical').Count) Critical, $(@($findings|Where-Object Severidade -eq 'High').Count) High)"
Write-Host "  Relatório: $htmlPath`n"
try { Start-Process $htmlPath } catch {}
