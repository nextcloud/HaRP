from fastapi import FastAPI, WebSocket
import uvicorn

APP = FastAPI()


@APP.get("/http")
def http_endpoint():
    # curl http://127.0.0.1:8780/exapps/wow/http
    return {"message": "Hello from HTTP endpoint!"}


@APP.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # websocat ws://127.0.0.1:8780/exapps/wow/ws
    await websocket.accept()
    await websocket.send_text("Hello from WebSocket!")
    await websocket.close()


if __name__ == "__main__":
    uvicorn.run("main:APP", host="127.0.0.1", port=24000, log_level="info")
