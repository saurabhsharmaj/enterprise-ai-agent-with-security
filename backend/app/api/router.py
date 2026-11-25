from fastapi import APIRouter

from app.api import admin, agents, business, health_me

api_router = APIRouter(prefix="/api")
api_router.include_router(health_me.router)
api_router.include_router(agents.router)
api_router.include_router(business.router)
api_router.include_router(admin.router)
