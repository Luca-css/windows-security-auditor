"""
Relatório de Acesso ao Servidor
Lê os logs de eventos do Windows e gera relatório HTML por usuário.
"""

import subprocess
import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict


# ─── Configuração ─────────────────────────────────────────────────────────────

DIAS_ATRAS      = 7        # quantos dias para trás analisar
MAX_EVENTOS     = 500      # limite de eventos por consulta
PASTA_SAIDA     = os.path.dirname(os.path.abspath(__file__))
ARQUIVO_HTML    = os.path.join(PASTA_SAIDA, "relatorio_acesso.html")
ARQUIVO_TXT     = os.path.join(PASTA_SAIDA, "relatorio_acesso.txt")

# IDs de eventos monitorados (Security Log)
EVENTOS = {
    "4624": "Login bem-sucedido",
    "4625": "Tentativa de login falhou",
    "4634": "Logoff",
    "4647": "Logoff iniciado pelo usuário",
    "4648": "Login com credenciais explícitas",
    "4672": "Privilégios especiais atribuídos",
    "4688": "Novo processo criado",
    "4720": "Conta de usuário criada",
    "4722": "Conta de usuário habilitada",
    "4725": "Conta de usuário desabilitada",
    "4726": "Conta de usuário excluída",
    "4740": "Conta bloqueada",
    "4756": "Membro adicionado a grupo",
    "4767": "Conta desbloqueada",
}

# Tipos de logon
TIPOS_LOGON = {
    "2":  "Interativo (local)",
    "3":  "Rede",
    "4":  "Lote (batch)",
    "5":  "Serviço",
    "7":  "Desbloqueio de tela",
    "8":  "Rede (texto puro)",
    "9":  "Novas credenciais",
    "10": "Interativo remoto (RDP)",
    "11": "Interativo em cache",
}


# ─── Coleta de eventos via PowerShell ─────────────────────────────────────────

def coletar_eventos():
    data_inicio = (datetime.now() - timedelta(days=DIAS_ATRAS)).strftime("%Y-%m-%dT%H:%M:%S")
    ids = ",".join(EVENTOS.keys())

    script_ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
$inicio = [datetime]::Parse('{data_inicio}')
$ids    = @({ids})

$eventos = Get-WinEvent -FilterHashtable @{{
    LogName   = 'Security'
    Id        = $ids
    StartTime = $inicio
}} -MaxEvents {MAX_EVENTOS} -ErrorAction SilentlyContinue

if (-not $eventos) {{ Write-Output '[]'; exit }}

$lista = foreach ($ev in $eventos) {{
    $xml  = [xml]$ev.ToXml()
    $data = $xml.Event.EventData.Data

    $props = @{{}}
    foreach ($d in $data) {{
        if ($d.Name) {{ $props[$d.Name] = $d.'#text' }}
    }}

    [PSCustomObject]@{{
        EventId     = $ev.Id
        TimeCreated = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Level       = $ev.LevelDisplayName
        Message     = $ev.Message -replace "`r`n"," " -replace '"',"'"
        SubjectUser = $props['SubjectUserName']
        TargetUser  = $props['TargetUserName']
        LogonType   = $props['LogonType']
        ProcessName = $props['NewProcessName']
        WorkStation = $props['WorkstationName']
        IpAddress   = $props['IpAddress']
        Computer    = $env:COMPUTERNAME
    }}
}}

$lista | ConvertTo-Json -Depth 3
"""

    print("  Consultando logs de segurança do Windows...")
    try:
        resultado = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script_ps],
            capture_output=True, text=True, timeout=120
        )
        saida = resultado.stdout.strip()
        if not saida or saida == "[]":
            return []

        dados = json.loads(saida)
        if isinstance(dados, dict):
            dados = [dados]
        return dados

    except subprocess.TimeoutExpired:
        print("  [AVISO] Timeout ao consultar logs. Verifique permissões de administrador.")
        return []
    except json.JSONDecodeError as e:
        print(f"  [AVISO] Erro ao interpretar JSON: {e}")
        return []
    except Exception as e:
        print(f"  [ERRO] {e}")
        return []


def coletar_usuarios_locais():
    script_ps = """
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description, PasswordLastSet
$users | ConvertTo-Json -Depth 2
"""
    try:
        resultado = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script_ps],
            capture_output=True, text=True, timeout=30
        )
        dados = json.loads(resultado.stdout.strip())
        if isinstance(dados, dict):
            dados = [dados]
        return dados
    except Exception:
        return []


# ─── Processamento dos dados ──────────────────────────────────────────────────

def processar_eventos(eventos):
    por_usuario = defaultdict(lambda: {
        "logins": [], "logoffs": [], "falhas": [], "processos": [],
        "privilegios": [], "outros": [], "ips": set(), "workstations": set()
    })

    for ev in eventos:
        eid   = str(ev.get("EventId", ""))
        tempo = ev.get("TimeCreated", "")
        user  = ev.get("TargetUser") or ev.get("SubjectUser") or "SISTEMA"
        user  = user.strip()

        if not user or user in ("-", "ANONYMOUS LOGON", ""):
            user = "SISTEMA/ANÔNIMO"

        ip = ev.get("IpAddress") or ""
        ws = ev.get("WorkStation") or ""
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            por_usuario[user]["ips"].add(ip)
        if ws and ws != "-":
            por_usuario[user]["workstations"].add(ws)

        tipo_logon = TIPOS_LOGON.get(str(ev.get("LogonType") or ""), "")
        desc = EVENTOS.get(eid, f"Evento {eid}")

        registro = {
            "tempo":  tempo,
            "evento": eid,
            "desc":   desc,
            "tipo":   tipo_logon,
            "proc":   ev.get("ProcessName") or "",
            "ip":     ip,
        }

        if eid == "4624":
            por_usuario[user]["logins"].append(registro)
        elif eid in ("4634", "4647"):
            por_usuario[user]["logoffs"].append(registro)
        elif eid == "4625":
            por_usuario[user]["falhas"].append(registro)
        elif eid == "4688":
            por_usuario[user]["processos"].append(registro)
        elif eid == "4672":
            por_usuario[user]["privilegios"].append(registro)
        else:
            por_usuario[user]["outros"].append(registro)

    return por_usuario


# ─── Geração do relatório HTML ────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; }
header { background: linear-gradient(135deg, #1a237e, #283593); color: white;
         padding: 24px 32px; }
header h1 { font-size: 1.6rem; }
header p  { opacity: .75; margin-top: 4px; font-size: .9rem; }
.container { max-width: 1100px; margin: 28px auto; padding: 0 16px; }
.resumo { display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr));
          gap: 14px; margin-bottom: 28px; }
.card { background: white; border-radius: 10px; padding: 18px 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,.08); }
.card .num  { font-size: 2rem; font-weight: 700; }
.card .label{ font-size: .8rem; color: #666; margin-top: 4px; }
.card.verde .num  { color: #2e7d32; }
.card.vermelho .num { color: #c62828; }
.card.azul .num   { color: #1565c0; }
.card.laranja .num{ color: #e65100; }
.usuario { background: white; border-radius: 10px; margin-bottom: 20px;
           box-shadow: 0 2px 8px rgba(0,0,0,.08); overflow: hidden; }
.usuario-header { padding: 14px 20px; display: flex; align-items: center;
                  gap: 14px; background: #e8eaf6; cursor: pointer;
                  user-select: none; }
.avatar { width: 40px; height: 40px; border-radius: 50%; background: #3949ab;
          color: white; display: flex; align-items: center; justify-content: center;
          font-weight: 700; font-size: 1.1rem; flex-shrink: 0; }
.usuario-header h2 { font-size: 1rem; flex: 1; }
.badges { display: flex; gap: 6px; flex-wrap: wrap; }
.badge { font-size: .72rem; padding: 2px 8px; border-radius: 20px;
         font-weight: 600; }
.badge.ok   { background:#c8e6c9; color:#1b5e20; }
.badge.erro { background:#ffcdd2; color:#b71c1c; }
.badge.info { background:#bbdefb; color:#0d47a1; }
.badge.warn { background:#ffe0b2; color:#bf360c; }
.usuario-body { padding: 0 20px 16px; display: none; }
.usuario-body.aberto { display: block; }
.secao { margin-top: 14px; }
.secao h3 { font-size: .85rem; font-weight: 600; color: #555; text-transform: uppercase;
            letter-spacing: .05em; margin-bottom: 6px; padding-bottom: 4px;
            border-bottom: 1px solid #eee; }
table { width: 100%; border-collapse: collapse; font-size: .82rem; }
th { background: #f5f5f5; text-align: left; padding: 7px 10px; color: #555; }
td { padding: 6px 10px; border-bottom: 1px solid #f0f0f0; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafafa; }
.pill-vermelho { color: #c62828; font-weight: 600; }
.pill-verde    { color: #2e7d32; font-weight: 600; }
.pill-azul     { color: #1565c0; }
.vazio { color: #aaa; font-size: .82rem; padding: 8px 0; }
footer { text-align: center; padding: 24px; color: #999; font-size: .8rem; }
"""

JS = """
function toggle(id) {
    const body = document.getElementById(id);
    body.classList.toggle('aberto');
}
"""

def badge(texto, tipo):
    return f'<span class="badge {tipo}">{texto}</span>'

def tabela(colunas, linhas, vazia="Nenhum registro."):
    if not linhas:
        return f'<p class="vazio">{vazia}</p>'
    ths = "".join(f"<th>{c}</th>" for c in colunas)
    trs = ""
    for linha in linhas:
        tds = "".join(f"<td>{c}</td>" for c in linha)
        trs += f"<tr>{tds}</tr>"
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"

def gerar_html(por_usuario, usuarios_locais, total_eventos, gerado_em):
    total_users = len(por_usuario)
    total_logins = sum(len(v["logins"]) for v in por_usuario.values())
    total_falhas = sum(len(v["falhas"]) for v in por_usuario.values())
    total_procs  = sum(len(v["processos"]) for v in por_usuario.values())

    # Mapa de usuários locais
    info_local = {u.get("Name","").lower(): u for u in usuarios_locais}

    resumo_html = f"""
    <div class="resumo">
      <div class="card azul"><div class="num">{total_users}</div><div class="label">Usuários detectados</div></div>
      <div class="card verde"><div class="num">{total_logins}</div><div class="label">Logins bem-sucedidos</div></div>
      <div class="card vermelho"><div class="num">{total_falhas}</div><div class="label">Tentativas falhas</div></div>
      <div class="card laranja"><div class="num">{total_procs}</div><div class="label">Processos registrados</div></div>
      <div class="card"><div class="num">{total_eventos}</div><div class="label">Eventos analisados</div></div>
    </div>"""

    usuarios_html = ""
    for idx, (usuario, dados) in enumerate(sorted(por_usuario.items())):
        uid = f"u{idx}"
        avatar_letra = usuario[0].upper() if usuario else "?"

        info = info_local.get(usuario.lower(), {})
        habilitado = info.get("Enabled")
        ultimo_login_local = info.get("LastLogon", "")

        badges_html = ""
        if dados["logins"]:
            badges_html += badge(f'{len(dados["logins"])} login(s)', "ok")
        if dados["falhas"]:
            badges_html += badge(f'{len(dados["falhas"])} falha(s)', "erro")
        if dados["processos"]:
            badges_html += badge(f'{len(dados["processos"])} processo(s)', "info")
        if dados["privilegios"]:
            badges_html += badge("Privilégios especiais", "warn")
        if habilitado is False:
            badges_html += badge("Conta desabilitada", "erro")

        ips_str = ", ".join(dados["ips"]) if dados["ips"] else "—"
        wss_str = ", ".join(dados["workstations"]) if dados["workstations"] else "—"

        # Logins
        rows_login = [
            (l["tempo"],
             f'<span class="pill-verde">{l["desc"]}</span>',
             l["tipo"] or "—",
             l["ip"] or "—")
            for l in sorted(dados["logins"], key=lambda x: x["tempo"], reverse=True)[:20]
        ]
        sec_logins = tabela(["Data/Hora","Evento","Tipo de logon","IP"], rows_login, "Sem logins registrados.")

        # Falhas
        rows_falha = [
            (l["tempo"],
             f'<span class="pill-vermelho">{l["desc"]}</span>',
             l["ip"] or "—")
            for l in sorted(dados["falhas"], key=lambda x: x["tempo"], reverse=True)[:20]
        ]
        sec_falhas = tabela(["Data/Hora","Evento","IP"], rows_falha, "Sem tentativas falhas.")

        # Processos
        rows_proc = [
            (l["tempo"], f'<span class="pill-azul">{os.path.basename(l["proc"]) if l["proc"] else "—"}</span>',
             l["proc"] or "—")
            for l in sorted(dados["processos"], key=lambda x: x["tempo"], reverse=True)[:30]
        ]
        sec_procs = tabela(["Data/Hora","Processo","Caminho completo"], rows_proc, "Sem processos registrados.")

        # Outros
        rows_outros = [
            (l["tempo"], l["desc"])
            for l in sorted(dados["outros"], key=lambda x: x["tempo"], reverse=True)[:20]
        ]
        sec_outros = tabela(["Data/Hora","Ação"], rows_outros, "Sem outros eventos.")

        usuarios_html += f"""
        <div class="usuario">
          <div class="usuario-header" onclick="toggle('{uid}')">
            <div class="avatar">{avatar_letra}</div>
            <h2>{usuario}</h2>
            <div class="badges">{badges_html}</div>
          </div>
          <div class="usuario-body" id="{uid}">
            <div class="secao">
              <h3>Informações gerais</h3>
              <table>
                <tr><th>IPs detectados</th><td>{ips_str}</td></tr>
                <tr><th>Estações de trabalho</th><td>{wss_str}</td></tr>
                {'<tr><th>Conta habilitada</th><td>' + ('Sim' if habilitado else 'Não') + '</td></tr>' if habilitado is not None else ''}
                {'<tr><th>Último logon (local)</th><td>' + str(ultimo_login_local) + '</td></tr>' if ultimo_login_local else ''}
              </table>
            </div>
            <div class="secao"><h3>Logins ({len(dados["logins"])})</h3>{sec_logins}</div>
            <div class="secao"><h3>Tentativas falhas ({len(dados["falhas"])})</h3>{sec_falhas}</div>
            <div class="secao"><h3>Processos iniciados ({len(dados["processos"])})</h3>{sec_procs}</div>
            <div class="secao"><h3>Outros eventos ({len(dados["outros"])})</h3>{sec_outros}</div>
          </div>
        </div>"""

    hostname = os.environ.get("COMPUTERNAME", "servidor")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório de Acesso — {hostname}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Relatório de Acesso ao Servidor</h1>
  <p>Servidor: <strong>{hostname}</strong> &nbsp;|&nbsp;
     Período: últimos <strong>{DIAS_ATRAS} dias</strong> &nbsp;|&nbsp;
     Gerado em: <strong>{gerado_em}</strong></p>
</header>
<div class="container">
  {resumo_html}
  {"".join(["<p style='color:#c62828;font-weight:600;margin-bottom:20px'>Nenhum evento encontrado. Execute como Administrador para acessar os logs de segurança.</p>"]) if not por_usuario else ""}
  {usuarios_html}
</div>
<footer>Relatório gerado automaticamente &bull; {gerado_em}</footer>
<script>{JS}</script>
</body>
</html>"""
    return html


# ─── Relatório em texto plano ─────────────────────────────────────────────────

def gerar_txt(por_usuario, gerado_em):
    linhas = []
    linhas.append("=" * 60)
    linhas.append("  RELATÓRIO DE ACESSO AO SERVIDOR")
    linhas.append(f"  Gerado em: {gerado_em}")
    linhas.append(f"  Período: últimos {DIAS_ATRAS} dias")
    linhas.append("=" * 60)

    for usuario, dados in sorted(por_usuario.items()):
        linhas.append(f"\n[ USUÁRIO: {usuario} ]")
        linhas.append(f"  Logins:   {len(dados['logins'])}")
        linhas.append(f"  Falhas:   {len(dados['falhas'])}")
        linhas.append(f"  Processos:{len(dados['processos'])}")
        linhas.append(f"  IPs:      {', '.join(dados['ips']) or '—'}")

        if dados["logins"]:
            linhas.append("  -- Últimos logins --")
            for l in sorted(dados["logins"], key=lambda x: x["tempo"], reverse=True)[:5]:
                linhas.append(f"     {l['tempo']}  {l['tipo'] or 'tipo?'}  IP:{l['ip'] or '—'}")

        if dados["falhas"]:
            linhas.append("  -- Tentativas falhas --")
            for l in sorted(dados["falhas"], key=lambda x: x["tempo"], reverse=True)[:5]:
                linhas.append(f"     {l['tempo']}  IP:{l['ip'] or '—'}")

    linhas.append("\n" + "=" * 60)
    return "\n".join(linhas)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 60)
    print("  RELATÓRIO DE ACESSO AO SERVIDOR")
    print(f"  Período: últimos {DIAS_ATRAS} dias")
    print("=" * 60)
    print()

    gerado_em = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    print("  [1/3] Coletando eventos de segurança...")
    eventos = coletar_eventos()
    print(f"       {len(eventos)} eventos encontrados.")

    print("  [2/3] Coletando usuários locais...")
    usuarios_locais = coletar_usuarios_locais()
    print(f"       {len(usuarios_locais)} usuários locais encontrados.")

    print("  [3/3] Gerando relatório...")
    por_usuario = processar_eventos(eventos)

    html = gerar_html(por_usuario, usuarios_locais, len(eventos), gerado_em)
    with open(ARQUIVO_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    txt = gerar_txt(por_usuario, gerado_em)
    with open(ARQUIVO_TXT, "w", encoding="utf-8") as f:
        f.write(txt)

    print()
    print(f"  Relatório HTML: {ARQUIVO_HTML}")
    print(f"  Relatório TXT:  {ARQUIVO_TXT}")
    print()

    # Resumo no terminal
    print(txt)

    # Abrir HTML automaticamente
    try:
        os.startfile(ARQUIVO_HTML)
    except Exception:
        pass


if __name__ == "__main__":
    if sys.platform != "win32":
        print("[AVISO] Este script foi feito para Windows.")
    main()
