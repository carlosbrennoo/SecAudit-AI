# SecAudit AI

Ferramenta que analisa a segurança da sua conta AWS automaticamente e gera um relatório em português usando Inteligência Artificial local. Sem chave de API, sem custo, sem limite — você roda, ela te fala o que está errado e o que fazer.

---

## A ideia

Configurar segurança na AWS é cheio de detalhe. Bucket público por acidente, usuário com mais permissão do que devia, porta aberta que não deveria estar — isso acontece o tempo todo, inclusive em empresas grandes.

O SecAudit AI entra na sua conta, vasculha tudo isso automaticamente e em paralelo, e usa uma IA rodando no seu próprio computador pra escrever um relatório em português que qualquer pessoa consegue entender.

---

## O que ele verifica

**Buckets S3**
Checa se algum bucket está público na internet sem querer e se os arquivos estão criptografados. Bucket público ou sem criptografia é dado exposto.

**Permissões IAM**
Verifica se algum usuário tem acesso de administrador sem precisar. Menos permissão, menos risco.

**Security Groups**
Detecta portas perigosas abertas pra internet, como a porta 22 (SSH) e 3389 (RDP). Porta aberta errada é porta de entrada pra invasor.

**Autenticação — OWASP A07**
Verifica se usuários estão sem MFA ativado e se alguma chave de acesso está ativa há mais de 90 dias sem ser trocada. Chave velha é chave vulnerável.

**Logs CloudTrail — OWASP A09**
Analisa os eventos das últimas 24 horas e detecta criação ou deleção de usuários, acessos de IPs públicos suspeitos, tentativas de login falhadas, ações em horário suspeito e uso do usuário root.

**Monitoramento EC2**
Verifica se as instâncias estão com monitoramento ativado. Sem monitoramento, você é cego pra ataques em andamento.

---

## Como funciona por baixo

**Auditoria paralela**

Cada módulo roda numa thread separada ao mesmo tempo usando `ThreadPoolExecutor`. Todos os serviços são verificados simultaneamente, o que reduz bastante o tempo de análise:

```python
with ThreadPoolExecutor(max_workers=6) as executor:
    futures = {executor.submit(fn): nome for nome, fn in VERIFICACOES.items()}
```

**Relatório com IA local via Ollama**

Depois da auditoria, todos os resultados são estruturados por seção e enviados pro Mistral rodando localmente via Ollama — sem internet, sem chave de API, sem custo:

```python
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

response = client.chat.completions.create(
    model="mistral",
    messages=[{"role": "user", "content": prompt}]
)
```

O modelo recebe um resumo com totais por severidade e os detalhes de cada seção, e devolve um relatório completo em português com problemas encontrados e ações corretivas recomendadas.

---

## Como rodar

**Pré-requisitos**

- Python 3.8+
- Conta AWS (Free Tier funciona)
- Ollama instalado em [ollama.com](https://ollama.com)

**Instala o modelo**

```bash
ollama pull mistral
```

Vai baixar uns 4GB na primeira vez. Depois fica salvo.

**Instala as dependências**

```bash
pip install boto3 python-dotenv openai
```

**Configuração**

Cria um arquivo `.env` na raiz do projeto:

```
AWS_KEY=sua_chave_aws_aqui
AWS_SECRET=sua_chave_secreta_aws_aqui
```

Nunca sobe o `.env` pro GitHub. O `.gitignore` já está configurado pra ignorar ele.

**Rodando**

Certifica que o Ollama está ativo:

```bash
ollama serve
```

Depois roda a auditoria:

```bash
python main.py
```

O relatório aparece no terminal e é salvo em `relatorio.txt`.

---

## Tecnologias

- **Python** — linguagem principal
- **boto3** — SDK oficial da AWS pra Python
- **ThreadPoolExecutor** — análise paralela dos módulos
- **Ollama + Mistral** — IA local, gratuita e sem limite
- **python-dotenv** — gerenciamento seguro de credenciais

---

## Proximas melhorias

- Interface gráfica
- Suporte a multiplas regioes AWS
- Exportar relatorio em PDF
- Integracao com Slack pra alertas em tempo real
- Historico de auditorias anteriores

---

## Autor

Desenvolvido por Carlos como parte da jornada pra se tornar Security AI Engineer.

---

Use a vontade, filhote.
