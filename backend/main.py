#!/usr/bin/env python3
"""
Main entry point for the AWS IAM Viewer backend application.
This file serves as the entry point when running the application directly.
"""

import uvicorn
from app.main import app

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
