from fastapi import FastAPI, WebSocket, Request
import uvicorn

APP = FastAPI()


@APP.get("/http")
def http_endpoint(request: Request):
    # curl http://127.0.0.1:8780/exapps/wow/http
    print(f"HTTP Request Headers:\n{request.headers}", flush=True)
    return {"message": "Hello from HTTP endpoint!"}


@APP.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # websocat ws://127.0.0.1:8780/exapps/wow/ws
    await websocket.accept()
    print(f"HTTP Request Headers:\n{websocket.headers}", flush=True)
    await websocket.send_text("Hello from WebSocket!")
    await websocket.close()


if __name__ == "__main__":
    uvicorn.run("main:APP", host="127.0.0.1", port=30000, log_level="info")


# patch code for "haproxy_agent.py"
"""
async def nc_get_exapp(app_id: str) -> ExApp | None:
    return ExApp(
        exapp_token="12345",
        exapp_version="1.1.1",
        port=23000,
        routes=[
            ExAppRoute(url="/http", access_level="PUBLIC"),
            ExAppRoute(url="/ws", access_level="PUBLIC")
        ]
    )
"""
