import boto3
from mangaba import Agent, Task, Crew, Process
import datetime
from datetime import datetime, timezone
from dotenv import load_dotenv
import os
from datetime import timedelta
load_dotenv()
encontrou = False

"""Abaixo tem onde o codigo vai pegar as credenciais, cria no seu editor um arquivo chamado ".env" e põe isso nele: 

    GEMINI_KEY=sua_chave_gemini_aqui
    AWS_KEY=sua_chave_aws_aqui
    AWS_SECRET=sua_chave_secreta_aws_aqui

E substitua os valores pelas suas chaves. O código vai ler essas variáveis de ambiente e usar para acessar a API do Gemini e da AWS. Nunca compartilhe essas chaves publicamente! Elas dão acesso total à sua conta. Se alguém tiver acesso a elas, pode causar muitos danos. Mantenha-as seguras e privadas.
"""

GEMINI_KEY = os.getenv('GEMINI_KEY')
AWS_KEY = os.getenv('AWS_KEY')
AWS_SECRET = os.getenv('AWS_SECRET')

session = boto3.Session(
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
    region_name='us-east-1'
)

resultados = []

print("*** Analisando Buckets S3 ***\n")
s3 = session.client('s3')
resposta = s3.list_buckets()
encontrou = False
for bucket in resposta['Buckets']:
    nome = bucket['Name']
    try:
        acl = s3.get_bucket_acl(Bucket=nome)
        publico = False
        for permissao in acl['Grants']:
            if 'URI' in permissao['Grantee']:
                if 'AllUsers' in permissao['Grantee']['URI']:
                    publico = True
        if publico:
            msg = f"[CRITICO] {nome} esta PUBLICO"
        else:
            msg = f"TUDO CERTO! {nome} esta privado"
        print(msg)
        resultados.append(msg)
        encontrou = True
        try:
            criptografia = s3.get_bucket_encryption(Bucket=nome)
            msg = f"TUDO CERTO! {nome} tem criptografia ativada"
            print(msg)
            resultados.append(msg)
        except:
            msg = f"[MEDIO] {nome} sem criptografia ativada"
            print(msg)
            resultados.append(msg)
    except Exception as e:
        print(f"ALGO ERRADO, {nome}: {e}")
if not encontrou:
    resultados.append("S3: nenhum bucket encontrado")

print("\n*** Analisando Usuarios IAM ***\n")
iam = session.client('iam')
usuarios = iam.list_users()
encontrou = False
for usuario in usuarios['Users']:
    nome = usuario['UserName']
    policies = iam.list_attached_user_policies(UserName=nome)
    for policy in policies['AttachedPolicies']:
        if policy['PolicyName'] == 'AdministratorAccess':
            msg = f"[MEDIO] {nome} tem acesso total"
            print(msg)
            resultados.append(msg)
            encontrou = True
    if not policies['AttachedPolicies']:
        msg = f"TUDO CERTO! {nome} sem policies diretas"
        print(msg)
        resultados.append(msg)
        encontrou = True
if not encontrou:
    msg = "Tudo certo por aqui! Nenhum usuario com acesso indevido"
    print(msg)
    resultados.append(msg)

print("\n *** Analisando chaves de acesso ***\n")
credenciais = iam.list_users()
for usuario in credenciais['Users']:
    nome = usuario['UserName']
    mfa = iam.list_mfa_devices(UserName=nome)
    if not mfa['MFADevices']:
        msg = f"PERIGO! {nome} não tem MFA ativado"
        print(msg)
        resultados.append(msg)
        encontrou = True
    chaves = iam.list_access_keys(UserName=nome)
    for chave in chaves['AccessKeyMetadata']:
        if chave['Status'] == 'Active':
            data_criacao = chave['CreateDate']
            agora = datetime.now(timezone.utc)
            idade = (agora - data_criacao).days
            if idade > 90:
                msg = f"PERIGO! {nome} tem chave ativa com {idade} dias"
                print(msg)
                resultados.append(msg)
                encontrou = True
if not encontrou:
    msg = "Tudo certo por aqui! Nenhuma chave de acesso com problemas"
    print(msg)
    resultados.append(msg)

print("\n*** Analisando Security Groups ***\n")
ec2 = session.client('ec2')
grupos = ec2.describe_security_groups()
encontrou = False
for grupo in grupos['SecurityGroups']:
    nome = grupo['GroupName']
    for regra in grupo['IpPermissions']:
        for ip in regra.get('IpRanges', []):
            if ip['CidrIp'] == '0.0.0.0/0':
                porta = regra.get('FromPort', 'todas')
                msg = f"PERIGO! {nome} com porta {porta} aberta"
                print(msg)
                resultados.append(msg)
                encontrou = True
if not encontrou:
    msg = "Tudo certo por aqui! Nenhuma porta perigosa aberta"
    print(msg)
    resultados.append(msg)

print("\n*** Analisando logs do CloudTrail ***\n")
cloudtrail = session.client('cloudtrail')
logs = cloudtrail.list_trails()
encontrou = False

inicio = datetime.now(timezone.utc) - timedelta(hours=24)

eventos = cloudtrail.lookup_events(
    StartTime=inicio
)
eventos_registrados = set()
eventos_registrados = set()

for evento in eventos['Events']:
    nome_evento = evento['EventName']
    usuario = evento.get('Username', 'sistema')
    horario = evento['EventTime']
    hora = horario.hour
    ip = evento.get('SourceIPAddress', '')

    # eventos suspeitos de IAM
    if nome_evento in ['CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy']:
        chave = f"iam-{nome_evento}-{usuario}"
        if chave not in eventos_registrados:
            eventos_registrados.add(chave)
            msg = f"ALERTA! Evento {nome_evento} por {usuario}"
            print(msg)
            resultados.append(msg)
            encontrou = True

    # IP publico suspeito
    if ip and not (ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('172.16')):
        chave = f"ip-{ip}-{nome_evento}"
        if chave not in eventos_registrados:
            eventos_registrados.add(chave)
            msg = f"ALERTA! Acesso de IP publico: {ip} por {usuario}"
            print(msg)
            resultados.append(msg)
            encontrou = True

    # tentativa de login falhada
    if nome_evento == 'ConsoleLogin':
        detalhes = evento.get('CloudTrailEvent', '')
        if '"errorMessage": "Failed authentication"' in detalhes:
            chave = f"login-{usuario}"
            if chave not in eventos_registrados:
                eventos_registrados.add(chave)
                msg = f"ALERTA! Tentativa de login falhada por {usuario}"
                print(msg)
                resultados.append(msg)
                encontrou = True

    # horario suspeito — só registra se ainda nao foi registrado como root
    # horario suspeito ou root
    if hora >= 0 and hora <= 6 or usuario == 'root':
        chave = f"suspeito-{nome_evento}-{usuario}"
        if chave not in eventos_registrados:
            eventos_registrados.add(chave)
            if usuario == 'root' and hora >= 0 and hora <= 6:
                msg = f"ALERTA! Evento {nome_evento} por root em horario suspeito: {horario}"
            elif usuario == 'root':
                msg = f"ALERTA! Evento {nome_evento} por usuario root"
            else:
                msg = f"ALERTA! Evento {nome_evento} por {usuario} em horario suspeito: {horario}"
            print(msg)
            resultados.append(msg)
            encontrou = True
if not encontrou:
    msg = "Tudo certo por aqui! Nenhum evento suspeito nas ultimas 24 horas"
    print(msg)
    resultados.append(msg)

print("\n*** Verificando monitoramento e alertas ***\n")
ec2 = session.client('ec2')
instancias = ec2.describe_instances()
encontrou = False
for reserva in instancias['Reservations']:
    for instancia in reserva['Instances']:
        id = instancia['InstanceId']
        nome = next((tag['Value'] for tag in instancia.get('Tags', []) if tag['Key'] == 'Name'), id)
        if 'Monitoring' in instancia and instancia['Monitoring']['State'] != 'enabled':
            msg = f"SE LIGA! {nome} com monitoramento desativado"
            print(msg)
            resultados.append(msg)
            encontrou = True
if not encontrou:
    msg = "Tudo certo por aqui! Todas as instancias com monitoramento ativado"
    print(msg)
    resultados.append(msg)

print("\n*** Análise completa! Gerando relatório ***\n")

criticos = [r for r in resultados if '[CRITICO]' in r]
medios = [r for r in resultados if '[MEDIO]' in r]
alertas = [r for r in resultados if 'ALERTA' in r]

dados = f"""Resumo da auditoria AWS:
- Problemas criticos: {len(criticos)}
- Problemas medios: {len(medios)}
- Alertas: {len(alertas)}

Criticos: {', '.join(criticos) if criticos else 'nenhum'}
Medios: {', '.join(medios) if medios else 'nenhum'}
Alertas: {', '.join(alertas) if alertas else 'nenhum'}"""

analista = Agent(
    role="Analista de Segurança",
    goal="Analisar resultados de auditoria AWS e gerar relatório claro em português",
    backstory="Especialista em segurança cloud com 10 anos de experiência",
    llm="google",
    api_key=GEMINI_KEY
    
)


if len(dados) > 1500:
    dados = dados[:1500] + "\n... (resultados resumidos)"

tarefa = Task(
    description=f"Com base nesses resultados de auditoria AWS, escreva um relatório claro em português com no máximo 8 linhas. Diga o que foi encontrado e se há algum problema. Não deixe perder informações. Resultados:\n\n{dados}",
    expected_output="Relatório completo de segurança em português",
    agent=analista
)


crew = Crew(
    agents=[analista],
    tasks=[tarefa],
    process=Process.SEQUENTIAL
)

resultado = crew.kickoff()
print(resultado.final_output)

with open("relatorio.txt", "w", encoding="utf-8") as f:
    f.write(resultado.final_output)

print("\nRelatório salvo em relatorio.txt")