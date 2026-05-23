import boto3
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

AWS_KEY    = os.getenv('AWS_KEY')
AWS_SECRET = os.getenv('AWS_SECRET')

session = boto3.Session(
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
    region_name='us-east-1'
)

# ─────────────────────────────────────────────
# Cada função retorna (secao, [resultados])
# ─────────────────────────────────────────────

def verificar_s3():
    resultados = []
    s3 = session.client('s3')
    print("[S3] Iniciando análise...")
    try:
        resposta = s3.list_buckets()
        for bucket in resposta['Buckets']:
            nome = bucket['Name']
            try:
                try:
                    config = s3.get_public_access_block(Bucket=nome)
                    block = config['PublicAccessBlockConfiguration']
                    publico = not all([
                        block.get('BlockPublicAcls', False),
                        block.get('IgnorePublicAcls', False),
                        block.get('BlockPublicPolicy', False),
                        block.get('RestrictPublicBuckets', False),
                    ])
                except Exception:
                    publico = True
                msg = f"[CRITICO] {nome} está PÚBLICO" if publico else f"[OK] {nome} está privado"
                resultados.append(msg)
                try:
                    s3.get_bucket_encryption(Bucket=nome)
                    resultados.append(f"[OK] {nome} tem criptografia ativada")
                except Exception:
                    resultados.append(f"[MEDIO] {nome} sem criptografia ativada")
            except Exception as e:
                resultados.append(f"[ERRO] {nome}: {e}")
        if not resultados:
            resultados.append("[OK] Nenhum bucket encontrado")
    except Exception as e:
        resultados.append(f"[ERRO] Falha ao listar buckets: {e}")
    print("[S3] Concluído.")
    return "Buckets S3", resultados


def verificar_iam():
    resultados = []
    iam = session.client('iam')
    print("[IAM] Iniciando análise...")
    try:
        paginator = iam.get_paginator('list_users')
        encontrou = False
        for page in paginator.paginate():
            for usuario in page['Users']:
                nome = usuario['UserName']
                policies = iam.list_attached_user_policies(UserName=nome)
                for policy in policies['AttachedPolicies']:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        resultados.append(f"[MEDIO] {nome} tem AdministratorAccess")
                        encontrou = True
                if not policies['AttachedPolicies']:
                    resultados.append(f"[OK] {nome} sem policies diretas")
                    encontrou = True
        if not encontrou:
            resultados.append("[OK] Nenhum usuário com acesso indevido")
    except Exception as e:
        resultados.append(f"[ERRO] {e}")
    print("[IAM] Concluído.")
    return "Permissões IAM", resultados


def verificar_chaves():
    resultados = []
    iam = session.client('iam')
    print("[CHAVES] Iniciando análise...")
    try:
        paginator = iam.get_paginator('list_users')
        encontrou = False
        agora = datetime.now(timezone.utc)
        for page in paginator.paginate():
            for usuario in page['Users']:
                nome = usuario['UserName']
                mfa = iam.list_mfa_devices(UserName=nome)
                if not mfa['MFADevices']:
                    resultados.append(f"[PERIGO] {nome} sem MFA ativado")
                    encontrou = True
                chaves = iam.list_access_keys(UserName=nome)
                for chave in chaves['AccessKeyMetadata']:
                    if chave['Status'] == 'Active':
                        idade = (agora - chave['CreateDate']).days
                        if idade > 90:
                            resultados.append(f"[PERIGO] {nome} tem chave ativa com {idade} dias sem rotação")
                            encontrou = True
        if not encontrou:
            resultados.append("[OK] Nenhuma chave de acesso com problemas")
    except Exception as e:
        resultados.append(f"[ERRO] {e}")
    print("[CHAVES] Concluído.")
    return "Autenticação e Chaves (OWASP A07)", resultados


def verificar_security_groups():
    resultados = []
    ec2 = session.client('ec2')
    print("[SG] Iniciando análise...")
    try:
        grupos = ec2.describe_security_groups()
        encontrou = False
        for grupo in grupos['SecurityGroups']:
            nome = grupo['GroupName']
            for regra in grupo['IpPermissions']:
                for ip in regra.get('IpRanges', []):
                    if ip['CidrIp'] == '0.0.0.0/0':
                        porta = regra.get('FromPort', 'todas')
                        resultados.append(f"[PERIGO] Security Group '{nome}' com porta {porta} aberta para 0.0.0.0/0")
                        encontrou = True
        if not encontrou:
            resultados.append("[OK] Nenhuma porta perigosa aberta")
    except Exception as e:
        resultados.append(f"[ERRO] {e}")
    print("[SG] Concluído.")
    return "Security Groups", resultados


def verificar_cloudtrail():
    resultados = []
    cloudtrail = session.client('cloudtrail')
    print("[CLOUDTRAIL] Iniciando análise...")
    try:
        inicio = datetime.now(timezone.utc) - timedelta(hours=24)
        eventos = cloudtrail.lookup_events(StartTime=inicio)
        registrados = set()
        encontrou = False

        EVENTOS_IAM_SUSPEITOS = {
            'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy'
        }

        for evento in eventos['Events']:
            nome_evento = evento['EventName']
            usuario     = evento.get('Username', 'sistema')
            horario     = evento['EventTime']
            hora        = horario.hour
            ip          = evento.get('SourceIPAddress', '')

            if nome_evento in EVENTOS_IAM_SUSPEITOS:
                chave = f"iam-{nome_evento}-{usuario}"
                if chave not in registrados:
                    registrados.add(chave)
                    resultados.append(f"[ALERTA] Evento IAM sensível: {nome_evento} executado por {usuario}")
                    encontrou = True

            if ip and not any(ip.startswith(p) for p in ('192.168', '10.', '172.16')):
                chave = f"ip-{ip}-{nome_evento}"
                if chave not in registrados:
                    registrados.add(chave)
                    resultados.append(f"[ALERTA] Acesso de IP público {ip} — evento: {nome_evento} por {usuario}")
                    encontrou = True

            if nome_evento == 'ConsoleLogin':
                detalhes = evento.get('CloudTrailEvent', '')
                if '"errorMessage": "Failed authentication"' in detalhes:
                    chave = f"login-{usuario}"
                    if chave not in registrados:
                        registrados.add(chave)
                        resultados.append(f"[ALERTA] Tentativa de login falhada por {usuario}")
                        encontrou = True

            if (0 <= hora <= 6) or usuario == 'root':
                chave = f"suspeito-{nome_evento}-{usuario}"
                if chave not in registrados:
                    registrados.add(chave)
                    if usuario == 'root' and (0 <= hora <= 6):
                        msg = f"[ALERTA] {nome_evento} pelo usuário root em horário suspeito ({horario})"
                    elif usuario == 'root':
                        msg = f"[ALERTA] {nome_evento} executado pelo usuário root"
                    else:
                        msg = f"[ALERTA] {nome_evento} por {usuario} em horário suspeito ({horario})"
                    resultados.append(msg)
                    encontrou = True

        if not encontrou:
            resultados.append("[OK] Nenhum evento suspeito nas últimas 24 horas")
    except Exception as e:
        resultados.append(f"[ERRO] {e}")
    print("[CLOUDTRAIL] Concluído.")
    return "Logs CloudTrail — últimas 24h (OWASP A09)", resultados


def verificar_ec2():
    resultados = []
    ec2 = session.client('ec2')
    print("[EC2] Iniciando análise...")
    try:
        paginator = ec2.get_paginator('describe_instances')
        encontrou = False
        for page in paginator.paginate():
            for reserva in page['Reservations']:
                for inst in reserva['Instances']:
                    inst_id = inst['InstanceId']
                    nome = next(
                        (tag['Value'] for tag in inst.get('Tags', []) if tag['Key'] == 'Name'),
                        inst_id
                    )
                    if inst.get('Monitoring', {}).get('State') != 'enabled':
                        resultados.append(f"[MEDIO] Instância '{nome}' com monitoramento desativado")
                        encontrou = True
        if not encontrou:
            resultados.append("[OK] Todas as instâncias com monitoramento ativado")
    except Exception as e:
        resultados.append(f"[ERRO] {e}")
    print("[EC2] Concluído.")
    return "Monitoramento EC2", resultados


# ─────────────────────────────────────────────
# Execução paralela
# ─────────────────────────────────────────────

VERIFICACOES = {
    "S3":              verificar_s3,
    "IAM":             verificar_iam,
    "Chaves":          verificar_chaves,
    "Security Groups": verificar_security_groups,
    "CloudTrail":      verificar_cloudtrail,
    "EC2":             verificar_ec2,
}

print("*** SecAudit AI — Iniciando auditoria paralela ***\n")

secoes = {}

with ThreadPoolExecutor(max_workers=6) as executor:
    futures = {executor.submit(fn): nome for nome, fn in VERIFICACOES.items()}
    for future in as_completed(futures):
        try:
            secao, resultados = future.result()
            secoes[secao] = resultados
        except Exception as e:
            secoes["Erro"] = [f"[ERRO] {e}"]

# ─────────────────────────────────────────────
# Montar dados estruturados por seção
# ─────────────────────────────────────────────

print("\n*** Análise completa! Gerando relatório ***\n")

todas_as_linhas = []
for secao, itens in secoes.items():
    todas_as_linhas.append(f"\n=== {secao} ===")
    for item in itens:
        todas_as_linhas.append(f"  {item}")

dados_estruturados = "\n".join(todas_as_linhas)

todos    = [item for itens in secoes.values() for item in itens]
criticos = [r for r in todos if '[CRITICO]' in r]
medios   = [r for r in todos if '[MEDIO]'   in r]
alertas  = [r for r in todos if '[ALERTA]'  in r]
perigos  = [r for r in todos if '[PERIGO]'  in r]

resumo = f"""RESUMO GERAL:
- Críticos : {len(criticos)}
- Médios   : {len(medios)}
- Alertas  : {len(alertas)}
- Perigos  : {len(perigos)}
"""

dados_finais = resumo + dados_estruturados

# ─────────────────────────────────────────────
# Relatório via Ollama (local, gratuito)
# ─────────────────────────────────────────────

print("Conectando ao Ollama local...\n")

client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

prompt = (
    "Você é um analista de segurança cloud com 10 anos de experiência. "
    "Escreva APENAS em português do Brasil, com linguagem clara e profissional. "
    "Nunca use inglês. "
    "Você recebeu os resultados de uma auditoria de segurança AWS organizados por seção. "
    "Escreva um relatório completo em português com as seguintes partes:\n"
    "1. Resumo executivo (visão geral dos problemas)\n"
    "2. Detalhamento por seção — explique cada problema encontrado e o risco associado\n"
    "3. Ações corretivas recomendadas — objetivas e ordenadas por prioridade\n"
    "Não omita nenhum item. Use os prefixos [CRITICO], [PERIGO], [ALERTA], [MEDIO] e [OK] "
    "para referenciar cada item.\n\n"
    f"{dados_finais}"
)

response = client.chat.completions.create(
    model="mistral",
    messages=[{"role": "user", "content": prompt}],
    max_tokens=8192
)

relatorio = response.choices[0].message.content

print(relatorio)

with open("relatorio.txt", "w", encoding="utf-8") as f:
    f.write(relatorio)

print("\nRelatório salvo em relatorio.txt")