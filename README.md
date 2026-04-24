# Windows Security Auditor

Ferramenta de auditoria de segurança para ambientes Windows Server. Coleta eventos do Security Event Log via PowerShell, detecta anomalias e gera relatório HTML interativo por usuário.

## Funcionalidades

- Auditoria de logins (sucesso/falha), logoffs, processos e privilégios
- Detecção de brute force (múltiplas falhas de login em janela de tempo)
- Inventário de usuários locais com status de conta
- Relatório HTML com filtros interativos e exportação para TXT
- Suporte a agendamento via Task Scheduler

## Eventos Monitorados

| ID | Descrição |
|----|-----------|
| 4624 | Login bem-sucedido |
| 4625 | Tentativa de login falhou |
| 4648 | Login com credenciais explícitas |
| 4672 | Privilégios especiais atribuídos |
| 4688 | Novo processo criado |
| 4720/4726 | Conta criada / excluída |
| 4740/4767 | Conta bloqueada / desbloqueada |

## Uso

```bash
# Requer execução como Administrador
python relatorio_servidor.py

# Personalizar período e limite de eventos
DIAS_ATRAS = 7
MAX_EVENTOS = 500
```

## Saída

- `relatorio_acesso.html` — relatório interativo com cards por usuário
- `relatorio_acesso.txt` — resumo em texto plano para logs/e-mail

## Requisitos

- Python 3.8+
- Windows Server 2016+ ou Windows 10/11
- Permissões de Administrador (acesso ao Security Log)

## Estrutura

```
windows-security-auditor/
├── relatorio_servidor.py   # script principal
├── requirements.txt        # sem dependências externas
└── README.md
```
