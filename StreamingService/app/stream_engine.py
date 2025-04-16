import asyncio
import json
from typing import AsyncGenerator
from datetime import datetime

with open("time_series.json") as f:
    time_series = json.load(f)

queue = []  # list of asyncio.Queue() for each subscriber
current_index = 0

async def broadcaster():
    global current_index
    while current_index < len(time_series):
        data_point = time_series[current_index]
        current_index += 1
        for q in queue:
            await q.put(data_point)
        await asyncio.sleep(30)  # simulate 1 second per point

async def subscribe() -> AsyncGenerator[str, None]:
    q = asyncio.Queue()
    queue.append(q)

    try:
        while True:
            item = await q.get()
            yield f"data: {json.dumps(item)}\n\n"
    except asyncio.CancelledError:
        queue.remove(q)
