"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from collections.abc import Collection

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path
from .backend import routers, database

# Initialize web host
app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities"
)

# Initialize database with sample data if empty
database.init_database()

# Mount the static files directory for serving the frontend
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(current_dir, "static")), name="static")

# Root endpoint to redirect to static index.html
@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")

# In-memory activity database
activities_db = database.activities_collection
Collection + [
    {
        "id": 4,
        "name": "Basketball Club",
        "category": "Sports",
        "description": "Join the basketball team for training and competitions."
    },
    {
        "id": 5,
        "name": "Swimming Team",
        "category": "Sports",
        "description": "Participate in swimming meets and improve your skills."
    },
    {
        "id": 6,
        "name": "Drama Club",
        "category": "Artistic",
        "description": "Act, direct, and produce plays and performances."
    },
    {
        "id": 7,
        "name": "Photography Society",
        "category": "Artistic",
        "description": "Explore photography techniques and showcase your work."
    },
    {
        "id": 8,
        "name": "Chess Club",
        "category": "Intellectual",
        "description": "Challenge your mind and compete in chess tournaments."
    },
    {
        "id": 9,
        "name": "Debate Team",
        "category": "Intellectual",
        "description": "Develop public speaking and argumentation skills."
    }
]

# Include routers
app.include_router(routers.activities.router)
app.include_router(routers.auth.router)
