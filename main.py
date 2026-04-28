from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Secure Docs API")

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

def get_current_user(authorization: str = Header(...)):
    user_id = authorization.replace("Bearer ", "")
    if user_id not in users_db:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return users_db[user_id]

# --- DEPENDÊNCIA NOVA: VALIDAÇÃO DE ADMIN ---
def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        # Retornamos 403 Forbidden para erros de permissão
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# --- ENDPOINTS CORRIGIDOS ---

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

@app.get("/admin/users")
# CORREÇÃO DA VULN 2: Usar a dependência que força a checagem do papel (Role)
def get_all_users(admin_user: dict = Depends(get_current_admin)):
    return {"users": users_db}