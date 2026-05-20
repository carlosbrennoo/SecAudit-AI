import boto3

session = boto3.Session(
    aws_access_key_id='SUA-ACCESS-KEY',
    aws_secret_access_key='SUA-SECRET-KEY',
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