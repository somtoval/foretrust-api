import os
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr
from database import Base, engine, SessionLocal
from models import News, Contact, User
from fastapi.middleware.cors import CORSMiddleware
from auth import (
    create_access_token,
    authenticate_user,
    get_current_active_user,
    create_admin_user,
    get_password_hash,
    get_current_user_from_refresh_token,
    create_refresh_token,
    REFRESH_TOKEN_EXPIRE_DAYS,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create admin user automatically
db = SessionLocal()
create_admin_user(db)
db.close()

app = FastAPI(title="News + Contact API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure upload directory exists
os.makedirs("uploads", exist_ok=True)

# Serve uploaded images
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# DB session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------ Schemas ------------------

# Auth Schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        orm_mode = True

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

# News Schema
class NewsResponse(BaseModel):
    id: int
    title: str
    content: str
    author: str
    image_url: Optional[str] = None
    created_at: datetime

    class Config:
        orm_mode = True

# Contact Schema
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

# ------------------ AUTH ENDPOINTS ------------------

@app.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login endpoint - returns JWT tokens"""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token (short-lived)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Create refresh token (long-lived)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

# Add new refresh token endpoint
@app.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str = Form(...),
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token"""
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required"
        )
    
    # Validate refresh token and get user
    user = await get_current_user_from_refresh_token(refresh_token, db)
    
    # Create new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Optionally create new refresh token (rotate refresh token)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    new_refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/logout")
async def logout(current_user: User = Depends(get_current_active_user)):
    """Logout endpoint (client should delete token)"""
    return {"message": "Successfully logged out"}

@app.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return current_user

@app.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    from auth import verify_password
    
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password")
    
    current_user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()
    
    return {"message": "Password changed successfully"}

# ------------------ NEWS ENDPOINTS (Protected) ------------------

@app.post("/news", response_model=NewsResponse)
async def create_news(
    title: str = Form(...),
    content: str = Form(...),
    author: str = Form("Anonymous"),
    image: UploadFile = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Protected
):
    """Create news article (requires authentication)"""
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
    """Get all news articles (public)"""
    return db.query(News).all()


@app.get("/news/{news_id}", response_model=NewsResponse)
def get_news(news_id: int, db: Session = Depends(get_db)):
    """Get single news article (public)"""
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
    current_user: User = Depends(get_current_active_user)  # Protected
):
    """Update news article (requires authentication)"""
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
def delete_news(
    news_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Protected
):
    """Delete news article (requires authentication)"""
    article = db.query(News).filter(News.id == news_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="News not found")

    db.delete(article)
    db.commit()
    return {"detail": "News deleted"}

# ------------------ CONTACT ENDPOINTS ------------------

@app.post("/contact", response_model=ContactResponse)
def create_contact(contact: ContactCreate, db: Session = Depends(get_db)):
    """Create contact submission (public)"""
    new_contact = Contact(**contact.dict())
    db.add(new_contact)
    db.commit()
    db.refresh(new_contact)
    return new_contact

@app.get("/contact", response_model=List[ContactResponse])
def get_contacts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Protected
):
    """Get all contacts (requires authentication)"""
    return db.query(Contact).all()

@app.get("/contact/{contact_id}", response_model=ContactResponse)
def get_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Protected
):
    """Get single contact (requires authentication)"""
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact

@app.delete("/contact/{contact_id}")
def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Protected
):
    """Delete contact message (requires authentication)"""
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"detail": "Contact deleted"}