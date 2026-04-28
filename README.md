# Estrutura do Desenvolvimento: Explorando Broken Access Control

# 1. O que é Broken Access Control

A falha de controle de acesso ocorre quando uma aplicação não restringe corretamente as permissões de usuários autenticados, permitindo acesso indevido a recursos. Segundo o OWASP Top 10, essa vulnerabilidade está entre as mais críticas, pois pode levar à exposição de dados sensíveis e escalonamento de privilégios.

## 2. Apresentação do sistema vulnerável

Foi desenvolvida uma API REST utilizando o framework FastAPI para simular um sistema de gerenciamento de documentos com autenticação simplificada baseada em headers HTTP.

Destaque intencionalmente:

- Banco fake (users_db, documents_db)
- Autenticação simulada (insegura de propósito)

## 3. Demonstração das vulnerabilidades

A API possui duas falhas clássicas de controle de acesso:

- IDOR (Insecure Direct Object Reference): No endpoint GET /documents/{doc_id}, o sistema verifica se o usuário forneceu um token de autorização, mas não valida se o documento solicitado pertence àquele usuário. A API apenas busca o ID no banco e retorna.

- Escalonamento de Privilégio Vertical: No endpoint GET /admin/users, qualquer usuário logado consegue visualizar a lista de todos os usuários do sistema, pois a rota não verifica o papel (role) do requisitante para garantir que ele é um administrador.

## 4. Análise de Dependências (SCA) com pip-audit

Descreva a primeira etapa do pipeline de segurança: verificar se as bibliotecas utilizadas possuem falhas conhecidas (CVEs).

Evidências a serem inseridas:

- Requirements antes.jpg (mostrando as versões defasadas).

- SCA - Antes.jpg (mostrando o pip-audit detectando 7 vulnerabilidades, incluindo falhas no pyjwt e starlette).

Ação de Correção: Mostre a atualização do arquivo de dependências (Requirements depois.jpg) e a nova rodada do teste provando que o ambiente está limpo (SCA - Depois.jpg).

Conclusão da Etapa: Conclua que o SCA é vital para evitar ataques de cadeia de suprimentos, mas não analisa o código escrito pela sua equipe. A aplicação agora está "segura" do ponto de vista de bibliotecas, mas a falha lógica continua lá.

## 5. Análise Estática (SAST) com Bandit: O Ponto Cego da Automação

Apresente o uso do Bandit para escanear o código-fonte em busca de falhas de segurança.

Evidência a ser inserida:
- SAST-Foto2.jpg (mostrando o terminal com o resultado "No issues identified").

Análise Crítica: Ferramentas SAST procuram por padrões de sintaxe ruins (como senhas no código, uso de eval(), ou injeções óbvias). O SAST não entende o contexto do negócio. Ele não sabe que o user2 não deveria ter permissão para ler o doc_id: 101. Para o analisador estático, a sintaxe de buscar no banco de dados e retornar um JSON está perfeitamente correta.

Esse artigo da OWASP TOP TEN explica bem o motivo pelo qual ferramentas não conseguem identificar erros em regras de negócio: https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control

## 6. O Falso Negativo na Varredura Dinâmica (DAST Automatizado)

Para esgotar as tentativas automatizadas, a API foi submetida a uma varredura ativa (Active Scan) pelo OWASP ZAP, guiada pela documentação Swagger (openapi.json) do FastAPI.

- Resultado: O scanner disparou centenas de payloads contra a API, mas identificou apenas uma vulnerabilidade de Risco Baixo (ausência do cabeçalho X-Content-Type-Options) (inserir imagem: Resultado-ataque-dast.png).

- Análise Crítica: Mais uma vez, ocorreu um falso negativo para a nossa vulnerabilidade crítica. Scanners DAST automatizados não conseguem realizar ataques complexos de IDOR sozinhos porque eles não compreendem a semântica dos dados. O robô não sabe que o "user2" e o "user1" são entidades distintas e que os dados de um não podem ser lidos pelo outro. Desde que o servidor retorne o Status HTTP 200 OK (sem travar a aplicação), a automação considera o comportamento normal.

## 7. A Intervenção Humana: Explorando o IDOR Manualmente (O Ataque)

Como as ferramentas automatizadas falharam em todas as camadas (SCA, SAST e DAST), a vulnerabilidade só pôde ser detectada através de Pentest Manual, utilizando o OWASP ZAP não como um scanner cego, mas como um Proxy de Interceptação.