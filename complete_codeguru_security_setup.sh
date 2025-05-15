#!/bin/bash

# Script para completar a configuração do CodeGuru Security após a conexão GitHub ser estabelecida
# Execute este script após completar a configuração da conexão GitHub no console AWS

set -e

# Configurações
STACK_NAME="CodeGuruSecuritySASTAnalysis"
GITHUB_REPO_URL=""
GITHUB_BRANCH="main"
REGION="us-east-1"
CONNECTION_ARN=""
SNS_TOPIC_ARN=""
SES_SENDER_EMAIL=""
SES_RECIPIENT_EMAIL=""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Completando a configuração do CodeGuru Security...${NC}"

# Verificar se as variáveis necessárias foram definidas
if [ -z "$GITHUB_REPO_URL" ] || [ -z "$CONNECTION_ARN" ] || [ -z "$SNS_TOPIC_ARN" ]; then
    echo -e "${RED}Erro: Variáveis necessárias não definidas.${NC}"
    echo "Por favor, edite o script e defina as variáveis GITHUB_REPO_URL, CONNECTION_ARN e SNS_TOPIC_ARN."
    exit 1
fi

if [ -z "$SES_SENDER_EMAIL" ] || [ -z "$SES_RECIPIENT_EMAIL" ]; then
    echo -e "${RED}Erro: E-mails do SES não definidos.${NC}"
    echo "Por favor, edite o script e defina as variáveis SES_SENDER_EMAIL e SES_RECIPIENT_EMAIL."
    exit 1
fi

# Verificar se a conexão está disponível
CONNECTION_STATUS=$(aws codestar-connections get-connection --connection-arn $CONNECTION_ARN --query 'ConnectionStatus' --output text --region $REGION)

if [ "$CONNECTION_STATUS" != "AVAILABLE" ]; then
    echo -e "${RED}Erro: A conexão GitHub não está disponível.${NC}"
    echo "Por favor, complete a configuração da conexão no console AWS primeiro."
    exit 1
fi

echo -e "${GREEN}Conexão GitHub verificada com sucesso.${NC}"

# Extrair o nome do repositório do URL
REPO_NAME=$(echo $GITHUB_REPO_URL | sed 's/.*github.com\/[^\/]*\/\([^\/]*\).*/\1/')

# Configurar o CodeGuru Security para analisar o repositório
echo "Configurando o CodeGuru Security para análise SAST..."
aws codeguru-security create-scan-repository \
    --name "$REPO_NAME" \
    --provider-type "GITHUB" \
    --connection-arn $CONNECTION_ARN \
    --repository-url "$GITHUB_REPO_URL" \
    --branch "$GITHUB_BRANCH" \
    --region $REGION

# Verificar novamente os e-mails no SES
echo "Verificando status dos e-mails no SES..."
SENDER_VERIFICATION_STATUS=$(aws ses get-identity-verification-attributes \
    --identities "$SES_SENDER_EMAIL" \
    --region $REGION \
    --query "VerificationAttributes.$SES_SENDER_EMAIL.VerificationStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")

RECIPIENT_VERIFICATION_STATUS=$(aws ses get-identity-verification-attributes \
    --identities "$SES_RECIPIENT_EMAIL" \
    --region $REGION \
    --query "VerificationAttributes.$SES_RECIPIENT_EMAIL.VerificationStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$SENDER_VERIFICATION_STATUS" != "Success" ] || [ "$RECIPIENT_VERIFICATION_STATUS" != "Success" ]; then
    echo -e "${RED}Erro: Um ou ambos os e-mails não estão verificados no SES.${NC}"
    echo "Por favor, verifique os e-mails antes de continuar."
    exit 1
fi

echo -e "${GREEN}E-mails verificados com sucesso no SES.${NC}"

# Iniciar uma análise SAST
echo "Iniciando análise SAST..."
aws codeguru-security create-scan \
    --repository-name "$REPO_NAME" \
    --scan-name "InitialScan" \
    --scan-type "FULL" \
    --region $REGION

echo -e "${GREEN}Configuração completa! O CodeGuru Security está agora configurado para realizar análise SAST no repositório GitHub.${NC}"
echo -e "${GREEN}Os relatórios de vulnerabilidades serão enviados para a função Lambda que usará o Bedrock para análise.${NC}"
echo -e "${GREEN}Um e-mail com o relatório será enviado para $SES_RECIPIENT_EMAIL.${NC}"
echo -e "${YELLOW}Nota: A primeira análise pode levar algum tempo para ser concluída.${NC}"
