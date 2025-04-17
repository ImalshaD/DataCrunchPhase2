from loadDataset import load_grouped_data
import asyncio
from typing import Dict, List, AsyncGenerator
import json

class BroadCaster:
    def __init__(self, key ,csv_path, delay=30):
        self.key = key
        self.delay = delay
        self.date_batches = load_grouped_data(csv_path)
        self.current_index = 0
        self.queue = []  # list of asyncio.Queue() for each subscriber
        self.max_subscribers = 10
        self.subscriber_count = 0
        self.started = False

    async def broadcast(self):
        if self.started:
            return
        self.started = True
        while self.current_index < len(self.date_batches):
            data_point = self.date_batches[self.current_index]
            self.current_index += 1
            for q in self.queue:
                await q.put(data_point)
            await asyncio.sleep(self.delay)  # simulate delay per point

    async def subscribe(self) -> AsyncGenerator[str, None]:
        if not self.started:
            yield "data: {\"error\": \"Broadcasting has not yet begun.\"}\n\n"
            return
        if self.subscriber_count >= self.max_subscribers:
            yield "data: {\"error\": \"Max subscribers reached.\"}\n\n"
            return
        q = asyncio.Queue()
        self.queue.append(q)
        self.subscriber_count += 1
        
        try:
            while True:
                item = await q.get()
                yield f"data: {json.dumps(item)}\n\n"
        except asyncio.CancelledError:
            self.queue.remove(q)
            self.subscriber_count -= 1
    
    def reset(self):
        self.current_index = 0
        self.queue = []

    async def restart(self):
        self.reset()
        await self.broadcast()

