from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/users")
def create_user():
    return {"id": 1}


@router.get("/api/items/{item_id}")
def get_item(item_id: int):
    return {"item_id": item_id}


@router.delete("/api/items/{item_id}")
def delete_item(item_id: int):
    return {"deleted": True}
