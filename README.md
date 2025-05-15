# AWS Security Analysis Tools

Este repositório contém scripts para configurar e utilizar ferramentas de análise de segurança da AWS para repositórios de código.

## Ferramentas Utilizadas

### Amazon CodeGuru Security (SAST)
O Amazon CodeGuru Security é uma ferramenta de análise estática de segurança (SAST) que usa machine learning para identificar vulnerabilidades de segurança e problemas de qualidade de código em seus repositórios. Ele analisa o código-fonte estaticamente, sem necessidade de execução, para detectar:

- Vulnerabilidades de segurança
- Problemas de conformidade
- Bugs de código
- Práticas de codificação inseguras

## Scripts Disponíveis

1. `provision_codeguru_security_sast.sh` - Configura o Amazon CodeGuru Security para análise SAST de um repositório GitHub
2. `complete_codeguru_security_setup.sh` - Completa a configuração após a conexão GitHub ser estabelecida

## Fluxo de Trabalho

1. O CodeGuru Security analisa o código do repositório GitHub
2. As vulnerabilidades detectadas são enviadas para uma função Lambda
3. A função Lambda usa o Amazon Bedrock para analisar as vulnerabilidades e sugerir correções
4. Um relatório detalhado é enviado por e-mail via Amazon SES

## Pré-requisitos

- AWS CLI configurado
- Permissões para criar recursos IAM, Lambda, SNS, SES, CodeGuru e DevOps Guru
- Repositório GitHub
- E-mails verificados no Amazon SES

## Como Usar

1. Edite o script `provision_codeguru_security_sast.sh` para definir as variáveis necessárias
2. Execute o script: `./provision_codeguru_security_sast.sh`
3. Complete a configuração da conexão GitHub no console AWS
4. Execute o script de conclusão: `./complete_codeguru_security_setup.sh`
