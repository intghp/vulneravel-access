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

Como as ferramentas automatizadas falharam em todas as camadas (SCA, SAST e DAST), a vulnerabilidade só pôde ser detectada através de Pentest Manual, utilizando o OWASP ZAP não como um scanner cego, mas como um Editor/Proxy de Interceptação de requisições.

Para provar a falha de Broken Access Control (IDOR), foi simulado o seguinte cenário de ataque:
Sabemos que o usuário user1 (Alice) possui um documento confidencial de ID 101. O objetivo do teste é verificar se o usuário user2 (Bob) consegue acessar esse recurso burlando as regras de negócio.

Passo a passo da exploração:

- Forjando a Requisição: Utilizando a interface de requisições manuais do ZAP, enviamos uma chamada HTTP do tipo GET diretamente para o recurso alvo (/documents/101). A manipulação crítica (tampering) ocorreu no cabeçalho HTTP: injetamos intencionalmente o header Authorization: Bearer user2. (Inserir imagem: Requisição.jpg - mostrando o cabeçalho manipulado com o usuário 2).

- A Quebra de Acesso (A Falha Comprovada): O servidor recebeu a requisição, validou que o token existia (ou seja, considerou o usuário 2 como autenticado), mas falhou em validar a "posse" daquele recurso específico. O servidor acatou o comando e processou a devolução dos dados. (Inserir imagem: Resposta.jpg - mostrando o status HTTP 200 OK).

- Vazamento de Dados: Como resultado final, o corpo da resposta entregou os dados de outra pessoa para o atacante, exibindo a seguinte carga útil (payload):

```bash
{"doc_id": 101, "content": "Declaração de Imposto de Renda da Alice - CONFIDENCIAL"}
```

Veredito do Teste: O ataque manual foi bem-sucedido. A intervenção e o raciocínio humano foram essenciais para manipular o estado da requisição e provar a falha que a automação ignorou, demonstrando exatamente por que falhas lógicas lideram a lista de maiores riscos em aplicações web.

## 8. Mitigação e Correção de Código

### 1. Correção da Vulnerabilidade 1: Escalonamento de Privilégios (Role)

Para proteger a rota de administradores, foi criada uma nova dependência (get_current_admin) que não apenas verifica se o usuário existe, mas valida se a sua role é estritamente igual a admin.

```bash
# --- DEPENDÊNCIA NOVA: VALIDAÇÃO DE ADMIN ---
def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        # Retorna 403 Forbidden para erros de permissão
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# --- ENDPOINT CORRIGIDO ---
@app.get("/admin/users")
def get_all_users(admin_user: dict = Depends(get_current_admin)):
    return {"users": users_db}
```

### 2. Correção da Vulnerabilidade 2: IDOR (Insecure Direct Object Reference)

Para mitigar o IDOR, o endpoint /documents/{doc_id} foi reescrito. Agora, a lógica não confia apenas na autenticação, mas implementa uma verificação estrita de posse do recurso (Ownership).

Se o ID do dono do documento (owner_id) for diferente do ID do usuário autenticado (current_user["id"]), o sistema rejeita a requisição, a menos que o usuário seja um administrador.

```bash
# --- ENDPOINT CORRIGIDO ---
@app.get("/documents/{doc_id}")
def read_document(doc_id: int, current_user: dict = Depends(get_current_user)):
    doc = documents_db.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # CORREÇÃO DA VULN 1 (IDOR): Verificação estrita de posse!
    # Se o usuário não for o dono E não for admin, acesso negado.
    if doc["owner_id"] != current_user["id"] and current_user["role"] != "admin":
         raise HTTPException(status_code=403, detail="You do not have access to this document")
    
    return {"doc_id": doc_id, "content": doc["content"]}
```

## 9. Conclusão Final

O desenvolvimento deste estudo evidenciou que um pipeline DevSecOps maduro necessita de uma abordagem em múltiplas camadas. Ferramentas de análise de composição (SCA) e testes estáticos (SAST) são vitais para mitigar componentes defasados e erros de sintaxe. No entanto, o Broken Access Control (A01:2021) lidera os riscos de segurança globais justamente por ser invisível a essas automações.

OBS: Extremamente importante encontrar fontes e referências confiáveis que evidenciem a ineficiência dos testes automatizados para as vulnerabilidades de Broken Access Control