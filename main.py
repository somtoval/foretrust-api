import os
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr
from database import Base, engine, SessionLocal
from models import News, Contact

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="News + Contact API")

# 📁 Ensure upload directory exists
os.makedirs("uploads", exist_ok=True)

# 🔗 Serve uploaded images
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# DB session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------ Schemas ------------------

# 📰 News Schema
class NewsResponse(BaseModel):
    id: int
    title: str
    content: str
    author: str
    image_url: Optional[str] = None
    created_at: datetime

    class Config:
        orm_mode = True

# 📩 Contact Schema
class ContactCreate(BaseModel):
    firstname: str
    lastname: str
    email: EmailStr
    message: str

class ContactResponse(ContactCreate):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


@app.get("/")
def home():
    return {"message": "Code is running ✅"}

# ------------------ NEWS ENDPOINTS ------------------

@app.post("/news", response_model=NewsResponse)
async def create_news(
    title: str = Form(...),
    content: str = Form(...),
    author: str = Form("Anonymous"),
    image: UploadFile = File(None),
    db: Session = Depends(get_db),
):
    image_url = None
    if image:
        file_path = f"uploads/{image.filename}"
        with open(file_path, "wb") as f:
            f.write(await image.read())
        image_url = f"/uploads/{image.filename}"

    new_article = News(title=title, content=content, author=author, image_url=image_url)
    db.add(new_article)
    db.commit()
    db.refresh(new_article)
    return new_article


@app.get("/news", response_model=List[NewsResponse])
def get_all_news(db: Session = Depends(get_db)):
    return db.query(News).all()


@app.get("/news/{news_id}", response_model=NewsResponse)
def get_news(news_id: int, db: Session = Depends(get_db)):
    article = db.query(News).filter(News.id == news_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="News not found")
    return article


@app.put("/news/{news_id}", response_model=NewsResponse)
async def update_news(
    news_id: int,
    title: str = Form(None),
    content: str = Form(None),
    author: str = Form(None),
    image: UploadFile = File(None),
    db: Session = Depends(get_db),
):
    article = db.query(News).filter(News.id == news_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="News not found")

    if title:
        article.title = title
    if content:
        article.content = content
    if author:
        article.author = author
    if image:
        file_path = f"uploads/{image.filename}"
        with open(file_path, "wb") as f:
            f.write(await image.read())
        article.image_url = f"/uploads/{image.filename}"

    db.commit()
    db.refresh(article)
    return article


@app.delete("/news/{news_id}")
def delete_news(news_id: int, db: Session = Depends(get_db)):
    article = db.query(News).filter(News.id == news_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="News not found")

    db.delete(article)
    db.commit()
    return {"detail": "News deleted"}

# ------------------ CONTACT ENDPOINTS ------------------

# 📩 Create a new contact submission
@app.post("/contact", response_model=ContactResponse)
def create_contact(contact: ContactCreate, db: Session = Depends(get_db)):
    new_contact = Contact(**contact.dict())
    db.add(new_contact)
    db.commit()
    db.refresh(new_contact)
    return new_contact

# 📩 Get all contact submissions
@app.get("/contact", response_model=List[ContactResponse])
def get_contacts(db: Session = Depends(get_db)):
    return db.query(Contact).all()

# 📩 Get one contact by ID
@app.get("/contact/{contact_id}", response_model=ContactResponse)
def get_contact(contact_id: int, db: Session = Depends(get_db)):
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact

# 📩 Delete a contact message
@app.delete("/contact/{contact_id}")
def delete_contact(contact_id: int, db: Session = Depends(get_db)):
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"detail": "Contact deleted"}
