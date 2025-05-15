#!/bin/bash

# Script para provisionar CodeGuru Security com análise SAST para repositório GitHub
# O relatório de vulnerabilidades será enviado para uma função Lambda
# que usará o Amazon Bedrock para analisar e sugerir correções

set -e

# Configurações
STACK_NAME="CodeGuruSecuritySASTAnalysis"
GITHUB_REPO_URL=""
GITHUB_BRANCH="main"
REGION="us-east-1"
LAMBDA_FUNCTION_NAME="CodeGuruSecurityVulnerabilityAnalyzer"
BEDROCK_MODEL_ID="anthropic.claude-3-sonnet-20240229-v1:0"
SNS_TOPIC_NAME="CodeGuruSecurityAlerts"
IAM_ROLE_NAME="CodeGuruSecuritySASTRole"

# Configurações do SES (Amazon Simple Email Service)
SES_SENDER_EMAIL=""
SES_RECIPIENT_EMAIL=""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Iniciando provisionamento da infraestrutura para análise SAST com CodeGuru Security...${NC}"

# Verificar se as variáveis necessárias foram definidas
if [ -z "$GITHUB_REPO_URL" ]; then
    echo -e "${RED}Erro: URL do repositório GitHub não definida.${NC}"
    echo "Por favor, edite o script e defina a variável GITHUB_REPO_URL."
    exit 1
fi

if [ -z "$SES_SENDER_EMAIL" ] || [ -z "$SES_RECIPIENT_EMAIL" ]; then
    echo -e "${RED}Erro: E-mails do SES não definidos.${NC}"
    echo "Por favor, edite o script e defina as variáveis SES_SENDER_EMAIL e SES_RECIPIENT_EMAIL."
    exit 1
fi

# Verificar se AWS CLI está instalado
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Erro: AWS CLI não está instalado.${NC}"
    echo "Por favor, instale o AWS CLI: https://aws.amazon.com/cli/"
    exit 1
fi

# Verificar se o usuário está autenticado na AWS
aws sts get-caller-identity &> /dev/null || {
    echo -e "${RED}Erro: Não foi possível autenticar com a AWS.${NC}"
    echo "Por favor, configure suas credenciais AWS: aws configure"
    exit 1
}

# Verificar se o e-mail do remetente está verificado no SES
echo "Verificando se o e-mail do remetente está verificado no SES..."
SENDER_VERIFICATION_STATUS=$(aws ses get-identity-verification-attributes \
    --identities "$SES_SENDER_EMAIL" \
    --region $REGION \
    --query "VerificationAttributes.$SES_SENDER_EMAIL.VerificationStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$SENDER_VERIFICATION_STATUS" != "Success" ]; then
    echo -e "${YELLOW}O e-mail do remetente não está verificado no SES. Enviando solicitação de verificação...${NC}"
    aws ses verify-email-identity \
        --email-address "$SES_SENDER_EMAIL" \
        --region $REGION
    echo -e "${YELLOW}Um e-mail de verificação foi enviado para $SES_SENDER_EMAIL.${NC}"
    echo -e "${YELLOW}Por favor, verifique o e-mail antes de continuar.${NC}"
    echo -e "${YELLOW}Pressione Enter para continuar quando o e-mail estiver verificado...${NC}"
    read -p ""
else
    echo -e "${GREEN}E-mail do remetente já verificado no SES.${NC}"
fi

# Verificar se o e-mail do destinatário está verificado no SES (necessário no modo sandbox)
echo "Verificando se o e-mail do destinatário está verificado no SES..."
RECIPIENT_VERIFICATION_STATUS=$(aws ses get-identity-verification-attributes \
    --identities "$SES_RECIPIENT_EMAIL" \
    --region $REGION \
    --query "VerificationAttributes.$SES_RECIPIENT_EMAIL.VerificationStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$RECIPIENT_VERIFICATION_STATUS" != "Success" ]; then
    echo -e "${YELLOW}O e-mail do destinatário não está verificado no SES. Enviando solicitação de verificação...${NC}"
    aws ses verify-email-identity \
        --email-address "$SES_RECIPIENT_EMAIL" \
        --region $REGION
    echo -e "${YELLOW}Um e-mail de verificação foi enviado para $SES_RECIPIENT_EMAIL.${NC}"
    echo -e "${YELLOW}Por favor, verifique o e-mail antes de continuar.${NC}"
    echo -e "${YELLOW}Pressione Enter para continuar quando o e-mail estiver verificado...${NC}"
    read -p ""
else
    echo -e "${GREEN}E-mail do destinatário já verificado no SES.${NC}"
fi

# Criar IAM Role para o CodeGuru Security e Lambda
echo "Criando IAM Role para CodeGuru Security e Lambda..."
aws iam create-role \
    --role-name $IAM_ROLE_NAME \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "codeguru-security.amazonaws.com",
                        "lambda.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }' \
    --region $REGION

# Anexar políticas necessárias
echo "Anexando políticas ao IAM Role..."
aws iam attach-role-policy \
    --role-name $IAM_ROLE_NAME \
    --policy-arn arn:aws:iam::aws:policy/AmazonBedrockFullAccess \
    --region $REGION

aws iam attach-role-policy \
    --role-name $IAM_ROLE_NAME \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
    --region $REGION

# Adicionar política para permitir envio de e-mails via SES
echo "Criando política para acesso ao SES..."
aws iam create-policy \
    --policy-name CodeGuruSecuritySESPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ses:SendEmail",
                    "ses:SendRawEmail"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --region $REGION

# Obter o ARN da política SES criada
SES_POLICY_ARN=$(aws iam list-policies --query "Policies[?PolicyName=='CodeGuruSecuritySESPolicy'].Arn" --output text --region $REGION)

# Anexar a política SES
aws iam attach-role-policy \
    --role-name $IAM_ROLE_NAME \
    --policy-arn $SES_POLICY_ARN \
    --region $REGION

# Criar política personalizada para acesso ao CodeGuru
echo "Criando política personalizada para acesso ao CodeGuru..."
aws iam create-policy \
    --policy-name CodeGuruSecurityPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "codeguru-reviewer:*",
                    "codeguru-security:*"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --region $REGION

# Obter o ARN da política criada
POLICY_ARN=$(aws iam list-policies --query "Policies[?PolicyName=='CodeGuruSecurityPolicy'].Arn" --output text --region $REGION)

# Anexar a política personalizada
aws iam attach-role-policy \
    --role-name $IAM_ROLE_NAME \
    --policy-arn $POLICY_ARN \
    --region $REGION

echo -e "${GREEN}IAM Role e políticas criadas com sucesso.${NC}"

# Criar SNS Topic para notificações
echo "Criando SNS Topic para notificações..."
SNS_TOPIC_ARN=$(aws sns create-topic \
    --name $SNS_TOPIC_NAME \
    --region $REGION \
    --query 'TopicArn' \
    --output text)

echo -e "${GREEN}SNS Topic criado: $SNS_TOPIC_ARN${NC}"

# Criar código da função Lambda
echo "Criando código da função Lambda..."
mkdir -p lambda_code
cat > lambda_code/index.py << 'EOL'
import json
import boto3
import os
import base64
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Configurar logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Inicializar clientes
bedrock_runtime = boto3.client('bedrock-runtime')
sns = boto3.client('sns')
ses = boto3.client('ses')

def send_email_report(analysis_results, vulnerability_count):
    """
    Envia um e-mail com o relatório de análise de vulnerabilidades usando o Amazon SES
    """
    try:
        sender = os.environ.get('SES_SENDER_EMAIL')
        recipient = os.environ.get('SES_RECIPIENT_EMAIL')
        
        if not sender or not recipient:
            logger.error("E-mails de remetente ou destinatário não configurados")
            return False
            
        # Criar o corpo do e-mail em HTML
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #232f3e; color: white; padding: 10px; text-align: center; }}
                .vulnerability {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .high {{ border-left: 5px solid #d13212; }}
                .medium {{ border-left: 5px solid #ff9900; }}
                .low {{ border-left: 5px solid #7fba00; }}
                pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Relatório de Análise de Vulnerabilidades</h2>
                </div>
                
                <p>Foram encontradas <strong>{vulnerability_count}</strong> vulnerabilidades no repositório.</p>
        """
        
        # Adicionar cada vulnerabilidade ao corpo do e-mail
        for i, result in enumerate(analysis_results):
            vuln = result.get('vulnerability', {})
            severity = vuln.get('severity', 'medium').lower()
            
            html_body += f"""
                <div class="vulnerability {severity}">
                    <h3>Vulnerabilidade #{i+1}: {vuln.get('type', 'Desconhecida')}</h3>
                    <p><strong>Severidade:</strong> {severity.upper()}</p>
                    <p><strong>Arquivo:</strong> {vuln.get('filePath', 'Desconhecido')}</p>
                    
                    <h4>Código Vulnerável:</h4>
                    <pre>{vuln.get('codeSnippet', 'Código não disponível')}</pre>
                    
                    <h4>Análise e Recomendações:</h4>
                    <div>{result.get('analysis', 'Análise não disponível').replace('\\n', '<br>')}</div>
                </div>
            """
        
        html_body += """
                <div class="footer">
                    <p>Este é um e-mail automático gerado pelo sistema de análise de vulnerabilidades.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Criar a mensagem de e-mail
        message = MIMEMultipart()
        message['Subject'] = f'Relatório de Vulnerabilidades - {vulnerability_count} encontradas'
        message['From'] = sender
        message['To'] = recipient
        
        # Anexar o corpo HTML
        part = MIMEText(html_body, 'html')
        message.attach(part)
        
        # Anexar o relatório completo como JSON
        attachment = MIMEApplication(json.dumps(analysis_results, indent=2).encode('utf-8'))
        attachment.add_header('Content-Disposition', 'attachment', filename='vulnerability_report.json')
        message.attach(attachment)
        
        # Enviar o e-mail
        response = ses.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={'Data': message.as_string()}
        )
        
        logger.info(f"E-mail enviado com sucesso: {response}")
        return True
        
    except Exception as e:
        logger.error(f"Erro ao enviar e-mail: {str(e)}")
        return False

def analyze_vulnerability(vulnerability_data):
    """
    Usa o Amazon Bedrock para analisar a vulnerabilidade e sugerir correções
    """
    try:
        # Extrair informações relevantes da vulnerabilidade
        code_snippet = vulnerability_data.get('codeSnippet', 'Código não disponível')
        vulnerability_type = vulnerability_data.get('type', 'Tipo desconhecido')
        severity = vulnerability_data.get('severity', 'Desconhecida')
        file_path = vulnerability_data.get('filePath', 'Caminho desconhecido')
        
        # Criar prompt para o modelo Bedrock
        prompt = f"""
        Analise a seguinte vulnerabilidade de segurança encontrada em um código:
        
        Tipo de vulnerabilidade: {vulnerability_type}
        Severidade: {severity}
        Arquivo: {file_path}
        
        Trecho de código com a vulnerabilidade:
        ```
        {code_snippet}
        ```
        
        Por favor, forneça:
        1. Uma explicação detalhada da vulnerabilidade
        2. Por que isso representa um risco de segurança
        3. Uma sugestão específica de código corrigido
        4. Melhores práticas para evitar esse tipo de vulnerabilidade no futuro
        """
        
        # Chamar o modelo Bedrock (Claude)
        model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        
        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            })
        )
        
        response_body = json.loads(response['body'].read().decode('utf-8'))
        analysis = response_body['content'][0]['text']
        
        return {
            'vulnerability': vulnerability_data,
            'analysis': analysis
        }
        
    except Exception as e:
        logger.error(f"Erro ao analisar vulnerabilidade: {str(e)}")
        return {
            'vulnerability': vulnerability_data,
            'analysis': f"Erro ao analisar: {str(e)}"
        }

def lambda_handler(event, context):
    """
    Função principal do Lambda que processa relatórios do CodeGuru Security
    """
    try:
        logger.info("Recebendo evento do CodeGuru Security")
        logger.info(json.dumps(event))
        
        # Verificar se o evento veio do SNS
        if 'Records' in event and len(event['Records']) > 0 and 'Sns' in event['Records'][0]:
            message = json.loads(event['Records'][0]['Sns']['Message'])
            
            # Verificar se é um relatório de vulnerabilidade
            if 'vulnerabilities' in message:
                vulnerabilities = message['vulnerabilities']
                
                results = []
                for vuln in vulnerabilities:
                    analysis = analyze_vulnerability(vuln)
                    results.append(analysis)
                
                # Publicar resultados no SNS
                sns.publish(
                    TopicArn=os.environ['SNS_TOPIC_ARN'],
                    Subject='Análise de Vulnerabilidades - Sugestões de Correção',
                    Message=json.dumps(results, indent=2)
                )
                
                # Enviar e-mail com o relatório
                send_email_report(results, len(results))
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': f'Analisadas {len(results)} vulnerabilidades com sucesso',
                        'results': results
                    })
                }
            else:
                logger.info("Evento recebido não contém vulnerabilidades")
                return {
                    'statusCode': 200,
                    'body': json.dumps({'message': 'Evento não contém vulnerabilidades'})
                }
        else:
            logger.info("Evento recebido não é do formato esperado")
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Formato de evento inválido'})
            }
            
    except Exception as e:
        logger.error(f"Erro ao processar evento: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
EOL

# Criar arquivo zip para o Lambda
echo "Criando arquivo zip para o Lambda..."
cd lambda_code
zip -r ../lambda_function.zip .
cd ..

# Aguardar a criação do IAM Role (pode levar alguns segundos para propagar)
echo "Aguardando propagação do IAM Role..."
sleep 10

# Obter o ARN do IAM Role
ROLE_ARN=$(aws iam get-role --role-name $IAM_ROLE_NAME --query 'Role.Arn' --output text --region $REGION)

# Criar função Lambda
echo "Criando função Lambda..."
aws lambda create-function \
    --function-name $LAMBDA_FUNCTION_NAME \
    --runtime python3.9 \
    --handler index.lambda_handler \
    --role $ROLE_ARN \
    --zip-file fileb://lambda_function.zip \
    --environment "Variables={SNS_TOPIC_ARN=$SNS_TOPIC_ARN,BEDROCK_MODEL_ID=$BEDROCK_MODEL_ID,SES_SENDER_EMAIL=$SES_SENDER_EMAIL,SES_RECIPIENT_EMAIL=$SES_RECIPIENT_EMAIL}" \
    --timeout 60 \
    --region $REGION

# Configurar permissão para o SNS invocar o Lambda
echo "Configurando permissão para o SNS invocar o Lambda..."
LAMBDA_ARN=$(aws lambda get-function --function-name $LAMBDA_FUNCTION_NAME --query 'Configuration.FunctionArn' --output text --region $REGION)

aws lambda add-permission \
    --function-name $LAMBDA_FUNCTION_NAME \
    --statement-id sns-invoke \
    --action lambda:InvokeFunction \
    --principal sns.amazonaws.com \
    --source-arn $SNS_TOPIC_ARN \
    --region $REGION

# Inscrever o Lambda no tópico SNS
echo "Inscrevendo o Lambda no tópico SNS..."
aws sns subscribe \
    --topic-arn $SNS_TOPIC_ARN \
    --protocol lambda \
    --notification-endpoint $LAMBDA_ARN \
    --region $REGION

# Configurar o CodeGuru Security para monitorar o repositório GitHub
echo "Configurando o CodeGuru Security para monitorar o repositório GitHub..."

# Criar conexão com o GitHub (usando CodeStar Connections)
CONNECTION_ARN=$(aws codestar-connections create-connection \
    --provider-type GitHub \
    --connection-name CodeGuruSecurityGitHubConnection \
    --region $REGION \
    --query 'ConnectionArn' \
    --output text)

echo -e "${YELLOW}IMPORTANTE: Você precisa completar a configuração da conexão GitHub manualmente.${NC}"
echo -e "${YELLOW}Acesse o console AWS > Developer Tools > Settings > Connections e complete a configuração da conexão.${NC}"
echo -e "${YELLOW}URL da conexão: https://$REGION.console.aws.amazon.com/codesuite/settings/connections${NC}"
echo -e "${YELLOW}Após completar a configuração, execute a segunda parte deste script.${NC}"

# Criar arquivo para a segunda parte do script
cat > complete_codeguru_security_setup.sh << EOL
#!/bin/bash

# Script para completar a configuração do CodeGuru Security após a conexão GitHub ser estabelecida
# Execute este script após completar a configuração da conexão GitHub no console AWS

set -e

# Configurações
STACK_NAME="CodeGuruSecuritySASTAnalysis"
GITHUB_REPO_URL="$GITHUB_REPO_URL"
GITHUB_BRANCH="$GITHUB_BRANCH"
REGION="$REGION"
CONNECTION_ARN="$CONNECTION_ARN"
SNS_TOPIC_ARN="$SNS_TOPIC_ARN"
SES_SENDER_EMAIL="$SES_SENDER_EMAIL"
SES_RECIPIENT_EMAIL="$SES_RECIPIENT_EMAIL"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Completando a configuração do CodeGuru Security...${NC}"

# Verificar se a conexão está disponível
CONNECTION_STATUS=\$(aws codestar-connections get-connection --connection-arn $CONNECTION_ARN --query 'ConnectionStatus' --output text --region $REGION)

if [ "\$CONNECTION_STATUS" != "AVAILABLE" ]; then
    echo -e "${RED}Erro: A conexão GitHub não está disponível.${NC}"
    echo "Por favor, complete a configuração da conexão no console AWS primeiro."
    exit 1
fi

echo -e "${GREEN}Conexão GitHub verificada com sucesso.${NC}"

# Extrair o nome do repositório do URL
REPO_NAME=\$(echo \$GITHUB_REPO_URL | sed 's/.*github.com\/[^\/]*\/\([^\/]*\).*/\1/')

# Configurar o CodeGuru Security para analisar o repositório
echo "Configurando o CodeGuru Security para análise SAST..."
aws codeguru-security create-scan-repository \
    --name "\$REPO_NAME" \
    --provider-type "GITHUB" \
    --connection-arn $CONNECTION_ARN \
    --repository-url "\$GITHUB_REPO_URL" \
    --branch "\$GITHUB_BRANCH" \
    --region $REGION

# Verificar novamente os e-mails no SES
echo "Verificando status dos e-mails no SES..."
SENDER_VERIFICATION_STATUS=\$(aws ses get-identity-verification-attributes \
    --identities "$SES_SENDER_EMAIL" \
    --region $REGION \
    --query "VerificationAttributes.$SES_SENDER_EMAIL.VerificationStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")

RECIPIENT_VERIFICATION_STATUS=\$(aws ses get-identity-verification-attributes \
    --identities "$SES_RECIPIENT_EMAIL" \
    --region $REGION \
    --query "VerificationAttributes.$SES_RECIPIENT_EMAIL.VerificationStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")

if [ "\$SENDER_VERIFICATION_STATUS" != "Success" ] || [ "\$RECIPIENT_VERIFICATION_STATUS" != "Success" ]; then
    echo -e "${RED}Erro: Um ou ambos os e-mails não estão verificados no SES.${NC}"
    echo "Por favor, verifique os e-mails antes de continuar."
    exit 1
fi

echo -e "${GREEN}E-mails verificados com sucesso no SES.${NC}"

# Iniciar uma análise SAST
echo "Iniciando análise SAST..."
aws codeguru-security create-scan \
    --repository-name "\$REPO_NAME" \
    --scan-name "InitialScan" \
    --scan-type "FULL" \
    --region $REGION

echo -e "${GREEN}Configuração completa! O CodeGuru Security está agora configurado para realizar análise SAST no repositório GitHub.${NC}"
echo -e "${GREEN}Os relatórios de vulnerabilidades serão enviados para a função Lambda que usará o Bedrock para análise.${NC}"
echo -e "${GREEN}Um e-mail com o relatório será enviado para $SES_RECIPIENT_EMAIL.${NC}"
echo -e "${YELLOW}Nota: A primeira análise pode levar algum tempo para ser concluída.${NC}"
EOL

chmod +x complete_codeguru_security_setup.sh

echo -e "${GREEN}Script de provisionamento criado com sucesso!${NC}"
echo -e "${YELLOW}Próximos passos:${NC}"
echo "1. Edite o script para definir as seguintes variáveis:"
echo "   - GITHUB_REPO_URL: URL do seu repositório GitHub"
echo "   - SES_SENDER_EMAIL: E-mail do remetente para notificações (será verificado pelo SES)"
echo "   - SES_RECIPIENT_EMAIL: E-mail do destinatário para notificações (será verificado pelo SES)"
echo "2. Execute o script: ./provision_codeguru_security_sast.sh"
echo "3. Complete a configuração da conexão GitHub no console AWS"
echo "4. Execute o script de conclusão: ./complete_codeguru_security_setup.sh"

# Limpar arquivos temporários
rm -rf lambda_code
rm -f lambda_function.zip

echo -e "${GREEN}Concluído!${NC}"
