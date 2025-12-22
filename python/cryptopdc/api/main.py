from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List
import asyncio
import uuid
import json
from cryptopdc.api.routes import tasks, results, algorithms, nodes
from cryptopdc.api.websocket import progress

app = FastAPI(
    title="CryptoPDC API",
    description="Distributed Cryptanalysis Framework API",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(tasks.router, prefix="/api/v1/tasks", tags=["tasks"])
app.include_router(results.router, prefix="/api/v1/results", tags=["results"])
app.include_router(algorithms.router, prefix="/api/v1/algorithms", tags=["algorithms"])
app.include_router(nodes.router, prefix="/api/v1/nodes", tags=["nodes"])

@app.get("/")
async def root():
    return {"message": "CryptoPDC API is running", "version": "1.0.0", "status": "online"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await progress.manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Process incoming WebSocket messages if any
            # For now, we mainly use this to push updates
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        progress.manager.disconnect(websocket)
