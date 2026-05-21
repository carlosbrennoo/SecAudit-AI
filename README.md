#  SecAudit AI

Ferramenta que analisa a segurança da sua conta AWS automaticamente e gera um relatório em português usando Inteligência Artificial. Sem complicação, sem linguagem de manual — você roda, ela te fala o que está errado e o que fazer.

---

## 💡 A ideia

Configurar segurança na AWS é cheio de detalhe. Bucket público por acidente, usuário com mais permissão do que devia, porta aberta que não deveria estar — isso acontece o tempo todo, inclusive em empresas grandes.

O SecAudit AI entra na sua conta, vasculha tudo isso automaticamente e ainda usa IA pra escrever um relatório em português que qualquer pessoa consegue entender.

---

## 🔍 O que ele verifica

**Buckets S3**
Checa se algum arquivo está público na internet sem querer. Um bucket público mal configurado já causou vazamentos enormes de dados em empresas do mundo todo.

**Permissões IAM**
Verifica se algum usuário tem acesso de administrador sem precisar. Menos permissão = menos risco.

**Security Groups**
Detecta portas perigosas abertas pra internet, como a porta 22 (SSH) e 3389 (RDP). Porta aberta errada é porta de entrada pra invasor.

**Autenticação - OWASP A07**
Verifica se usuários estão sem MFA ativado e se alguma chave de acesso está ativa há mais de 90 dias sem ser trocada. Chave velha é chave vulnerável.

---

##  Como funciona por baixo

O código é dividido em duas partes principais:

**Parte 1 - Auditoria com boto3**

`boto3` é a biblioteca oficial da AWS pra Python. Com ela o código se conecta na sua conta e busca as informações de cada serviço:

```python
s3 = session.client('s3')
resposta = s3.list_buckets()
```

Cada resultado é guardado numa lista chamada `resultados`. Se achou algo errado, adiciona uma mensagem de PERIGO. Se está tudo certo, adiciona uma mensagem de OK.

**Parte 2 - Relatório com IA usando Mangaba AI**

Depois da auditoria, os resultados são enviados pra um agente de IA criado com o [Mangaba AI](https://github.com/Mangaba-ai/mangaba_ai) - um framework brasileiro de agentes inteligentes - que usa o Google Gemini pra escrever o relatório final em português:

```python
analista = Agent(
    role="Analista de Segurança",
    goal="Gerar relatório claro em português",
    backstory="Especialista em segurança cloud",
    llm="google",
    api_key=GEMINI_KEY
)
```

O agente recebe os dados da auditoria, analisa e devolve um relatório explicando o que foi encontrado e o que fazer.

---

##  Como rodar

### Pré-requisitos

- Python 3.8+
- Conta AWS (Free Tier funciona)
- Chave de API do Google Gemini - gratuita em [aistudio.google.com](https://aistudio.google.com)

### Instalação

```bash
git clone https://github.com/seu-usuario/secaudit-ai.git
cd secaudit-ai
pip install boto3 mangaba python-dotenv
```

### Configuração

Cria um arquivo `.env` na raiz do projeto:

```
GEMINI_KEY=sua_chave_gemini_aqui
AWS_KEY=sua_chave_aws_aqui
AWS_SECRET=sua_chave_secreta_aws_aqui
```

> ⚠️ Nunca sobe o `.env` pro GitHub. O `.gitignore` já está configurado pra ignorar ele.

### Rodando

```bash
python main.py
```

O relatório aparece no terminal e é salvo em `relatorio.txt`.

---

## 🛠️ Tecnologias

- **Python** - linguagem principal
- **boto3** - SDK oficial da AWS pra Python
- **[Mangaba AI](https://github.com/Mangaba-ai/mangaba_ai)** - framework brasileiro de agentes de IA. Site oficial: [mangaba.ia.br](https://www.mangaba.ia.br)
- **Google Gemini** - modelo de IA pra geração do relatório
- **python-dotenv** - gerenciamento seguro de credenciais

---

##  Próximas melhorias

- [ ] Verificar criptografia dos buckets S3
- [ ] Suporte a múltiplas regiões AWS
- [ ] Exportar relatório em PDF
- [ ] Interface web pra visualização dos resultados
- [ ] Integração com Slack pra alertas em tempo real

---

##  Autor

Desenvolvido por Carlos como parte da jornada pra se tornar **Security AI Engineer**.

---

Use à vontade, filhote. 🤙
