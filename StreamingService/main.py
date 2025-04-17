from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from app.stream_engine import broadcaster, subscribe
import asyncio

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcaster())

@app.get("/stream")
async def stream():
    return StreamingResponse(subscribe(), media_type="text/event-stream")