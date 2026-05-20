import boto3

session = boto3.Session(
    aws_access_key_id='SUA_CHAVE_DE_ACESSO_AQUI', #ACCESS KEY
    aws_secret_access_key='SUA_CHAVE_SECRETA_AQUI', #SECRECT KEY 
    region_name='us-east-1' #muda pra region_name='sa-east-1' se quer a região aqui do brasil, em sao paulo
)

s3 = session.client('s3')
resposta = s3.list_buckets()

print("*** Auditoria de Buckets S3 ***\n")

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
            print(f"PERIGO - {nome} esta PUBLICO")
        else:
            print(f"OK     - {nome} esta privado")
    
    except Exception as e:
        print(f"ERRO   - {nome}: {e}")

print("\n*** Auditoria de Usuarios IAM ***\n")

iam = session.client('iam')
usuarios = iam.list_users()

for usuario in usuarios['Users']:
    nome = usuario['UserName']
    policies = iam.list_attached_user_policies(UserName=nome)
    
    for policy in policies['AttachedPolicies']:
        if policy['PolicyName'] == 'AdministratorAccess':
            print(f"ATENCAO - {nome} tem acesso total (AdministratorAccess)")
    
    if not policies['AttachedPolicies']:
        print(f"OK      - {nome} sem policies diretas")