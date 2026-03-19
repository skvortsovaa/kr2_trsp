from typing import Optional
import re
import time
import uuid
from datetime import datetime

from fastapi import (
    FastAPI,
    HTTPException,
    Response,
    Cookie,
    Request,
    Header,
    Depends,
    Query,
)
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from itsdangerous import Signer, BadSignature

app = FastAPI()

SECRET_KEY = "super_secret_key_for_kr2"
signer = Signer(SECRET_KEY)

SESSION_COOKIE_NAME = "session_token"
SESSION_MAX_AGE = 300  # 5 минут
SESSION_REFRESH_MIN = 180  # 3 минуты

VALID_USERNAME = "user123"
VALID_PASSWORD = "password123"


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = Field(default=None, gt=0)
    is_subscribed: Optional[bool] = None


class CommonHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    user_agent: str = Field(alias="User-Agent")
    accept_language: str = Field(alias="Accept-Language")

    @field_validator("accept_language")
    @classmethod
    def validate_accept_language(cls, value: str) -> str:
        pattern = r"^[a-zA-Z]{2,3}(?:-[a-zA-Z]{2,4})?(?:,[a-zA-Z]{2,3}(?:-[a-zA-Z]{2,4})?(?:;q=\d(?:\.\d{1,3})?)?)*$"
        if not re.fullmatch(pattern, value):
            raise ValueError("Invalid Accept-Language format")
        return value


sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99},
]


def create_session_token(user_id: str, timestamp: int) -> str:
    payload = f"{user_id}.{timestamp}"
    token = signer.sign(payload).decode()
    return token


def verify_session_token(token: str) -> tuple[str, int]:
    try:
        unsigned_value = signer.unsign(token).decode()
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid session")

    parts = unsigned_value.split(".", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Invalid session")

    user_id, timestamp_str = parts

    try:
        uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid session")

    if not timestamp_str.isdigit():
        raise HTTPException(status_code=401, detail="Invalid session")

    timestamp = int(timestamp_str)
    now = int(time.time())

    if timestamp > now:
        raise HTTPException(status_code=401, detail="Invalid session")

    return user_id, timestamp


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE,
    )


def build_user_profile(user_id: str) -> dict:
    return {
        "user_id": user_id,
        "username": VALID_USERNAME,
        "role": "user",
        "message": "Вы успешно авторизованы",
    }


def check_session_and_refresh_if_needed(
    response: Response,
    session_token: Optional[str],
) -> dict:
    if not session_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id, last_activity = verify_session_token(session_token)

    now = int(time.time())
    elapsed = now - last_activity

    if elapsed > SESSION_MAX_AGE:
        raise HTTPException(status_code=401, detail="Session expired")

    if SESSION_REFRESH_MIN <= elapsed < SESSION_MAX_AGE:
        new_token = create_session_token(user_id, now)
        set_session_cookie(response, new_token)

    return build_user_profile(user_id)


async def parse_login_data(request: Request) -> tuple[str, str]:
    content_type = request.headers.get("content-type", "").lower()

    if "application/json" in content_type:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
    else:
        raise HTTPException(
            status_code=400,
            detail="Content-Type must be application/json or form data",
        )

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    return username, password


def get_common_headers(
    user_agent: Optional[str] = Header(default=None, alias="User-Agent"),
    accept_language: Optional[str] = Header(default=None, alias="Accept-Language"),
) -> CommonHeaders:
    if not user_agent or not accept_language:
        raise HTTPException(
            status_code=400,
            detail="User-Agent and Accept-Language headers are required",
        )

    try:
        return CommonHeaders(
            **{
                "User-Agent": user_agent,
                "Accept-Language": accept_language,
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/create_user")
def create_user(user: UserCreate):
    return user


@app.get("/products/search")
def search_products(
    keyword: str,
    category: Optional[str] = None,
    limit: int = Query(default=10, ge=1),
):
    results = []

    for product in sample_products:
        if keyword.lower() in product["name"].lower():
            if category:
                if product["category"].lower() == category.lower():
                    results.append(product)
            else:
                results.append(product)

    return results[:limit]


@app.get("/product/{product_id}")
def get_product(product_id: int):
    for product in sample_products:
        if product["product_id"] == product_id:
            return product

    raise HTTPException(status_code=404, detail="Product not found")


@app.post("/login")
async def login(request: Request, response: Response):
    username, password = await parse_login_data(request)

    if username != VALID_USERNAME or password != VALID_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user_id = str(uuid.uuid4())
    now = int(time.time())
    session_token = create_session_token(user_id, now)

    set_session_cookie(response, session_token)

    return {
        "message": "Login successful",
        "session_token": session_token,
    }


@app.get("/user")
def get_user(
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    return check_session_and_refresh_if_needed(response, session_token)


@app.get("/profile")
def get_profile(
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    return check_session_and_refresh_if_needed(response, session_token)


@app.get("/headers")
def read_headers(headers: CommonHeaders = Depends(get_common_headers)):
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }


@app.get("/info")
def read_info(
    response: Response,
    headers: CommonHeaders = Depends(get_common_headers),
):
    response.headers["X-Server-Time"] = datetime.now().isoformat()

    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }
