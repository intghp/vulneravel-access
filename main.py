from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Vulnerable Docs API")

# --- BANCO DE DADOS FALSO ---
users_db = {
    "user1": {"id": 1, "role": "user", "name": "Alice"},
    "user2": {"id": 2, "role": "user", "name": "Bob"},
    "admin1": {"id": 3, "role": "admin", "name": "Charlie"}
}

documents_db = {
    101: {"owner_id": 1, "content": "Declaração de Imposto de Renda da Alice - CONFIDENCIAL"},
    102: {"owner_id": 2, "content": "Exames médicos do Bob - CONFIDENCIAL"},
    103: {"owner_id": 3, "content": "Senhas do Servidor - RESTRITO"}
}

# --- MODELOS ---
class Document(BaseModel):
    id: int
    content: str

# --- DEPENDÊNCIA VULNERÁVEL DE AUTENTICAÇÃO ---
def get_current_user(authorization: str = Header(...)):
    """Simula uma verificação de token. Lê o usuário diretamente do header."""
    user_id = authorization.replace("Bearer ", "")
    if user_id not in users_db:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return users_db[user_id]

# --- ENDPOINTS COM BROKEN ACCESS CONTROL ---

@app.get("/documents/{doc_id}")
def read_document(doc_id: int, authorization: str = Header(...)):
    """
    VULNERABILIDADE 1: IDOR (Insecure Direct Object Reference)
    O sistema verifica se o usuário está logado, mas não verifica se o 
    documento pertence a ele.
    """
    get_current_user(authorization) # Apenas checa se está logado
    
    doc = documents_db.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return {"doc_id": doc_id, "content": doc["content"]}

@app.get("/admin/users")
def get_all_users(authorization: str = Header(...)):
    """
    VULNERABILIDADE 2: Falta de Validação de Permissão (Role)
    Qualquer usuário logado consegue acessar uma rota administrativa.
    """
    get_current_user(authorization) # Falha: não verifica se role == 'admin'
    return {"users": users_db}