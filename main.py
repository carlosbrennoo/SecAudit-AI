import boto3
from mangaba import Agent, Task, Crew, Process

GEMINI_KEY = 'sua chave_api_google_gemini_aqui'

AWS_KEY    = 'sua chave_aws_aqui'
AWS_SECRET = 'sua chave_secreta_aws_aqui'

session = boto3.Session(
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
    region_name='us-east-1'
)

resultados = []

print("=== Auditoria de Buckets S3 ===\n")
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
            msg = f"PERIGO - {nome} esta PUBLICO"
        else:
            msg = f"OK     - {nome} esta privado"
        print(msg)
        resultados.append(msg)
        encontrou = True
    except Exception as e:
        print(f"ERRO   - {nome}: {e}")
if not encontrou:
    resultados.append("S3: nenhum bucket encontrado")

print("\n=== Auditoria de Usuarios IAM ===\n")
iam = session.client('iam')
usuarios = iam.list_users()
encontrou = False
for usuario in usuarios['Users']:
    nome = usuario['UserName']
    policies = iam.list_attached_user_policies(UserName=nome)
    for policy in policies['AttachedPolicies']:
        if policy['PolicyName'] == 'AdministratorAccess':
            msg = f"PERIGO - {nome} tem acesso total"
            print(msg)
            resultados.append(msg)
            encontrou = True
    if not policies['AttachedPolicies']:
        msg = f"OK     - {nome} sem policies diretas"
        print(msg)
        resultados.append(msg)
        encontrou = True
if not encontrou:
    msg = "OK - Nenhum usuario com acesso indevido"
    print(msg)
    resultados.append(msg)

print("\n=== Auditoria de Security Groups ===\n")
ec2 = session.client('ec2')
grupos = ec2.describe_security_groups()
encontrou = False
for grupo in grupos['SecurityGroups']:
    nome = grupo['GroupName']
    for regra in grupo['IpPermissions']:
        for ip in regra.get('IpRanges', []):
            if ip['CidrIp'] == '0.0.0.0/0':
                porta = regra.get('FromPort', 'todas')
                msg = f"PERIGO - {nome} com porta {porta} aberta"
                print(msg)
                resultados.append(msg)
                encontrou = True
if not encontrou:
    msg = "OK - Nenhuma porta perigosa aberta"
    print(msg)
    resultados.append(msg)

print("\n=== Gerando relatorio com IA ===\n")

analista = Agent(
    role="Analista de Segurança",
    goal="Analisar resultados de auditoria AWS e gerar relatório claro em português",
    backstory="Especialista em segurança cloud com 10 anos de experiência",
    llm="google",
    api_key=GEMINI_KEY
)


dados = "\n".join(resultados)

tarefa = Task(
    description=f"Analise esses resultados de auditoria AWS e escreva um relatório em português simples explicando o que foi encontrado e o que fazer para corrigir:\n\n{dados}",
    expected_output="Relatório de segurança em português com problemas encontrados e recomendações",
    agent=analista
)

crew = Crew(
    agents=[analista],
    tasks=[tarefa],
    process=Process.SEQUENTIAL
)

resultado = crew.kickoff()
print(resultado.final_output)