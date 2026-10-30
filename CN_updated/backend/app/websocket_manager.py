import logging
from typing import Dict, List, Optional
from fastapi import WebSocket

logger = logging.getLogger("websocket_manager")

class ConnectionManager:
    """Manages active WebSocket connections for real-time messaging."""

    def __init__(self):
        # Maps lowercase username to active WebSocket instance
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket, subprotocol: str = "cypherchat") -> None:
        """Accept WebSocket connection and register user."""
        await websocket.accept(subprotocol=subprotocol)
        key = username.lower()
        self.active_connections[key] = websocket
        logger.info(f"User '{username}' connected. Total active: {len(self.active_connections)}")
        
        # Broadcast online status to all other users
        await self.broadcast({
            "type": "user_status",
            "username": username,
            "status": "online"
        }, exclude=username)

    async def disconnect(self, username: str) -> None:
        """Unregister user connection and broadcast offline status."""
        key = username.lower()
        if key in self.active_connections:
            del self.active_connections[key]
            logger.info(f"User '{username}' disconnected. Total active: {len(self.active_connections)}")
            
            # Broadcast offline status to remaining users
            await self.broadcast({
                "type": "user_status",
                "username": username,
                "status": "offline"
            }, exclude=username)

    def is_online(self, username: str) -> bool:
        """Check if a specific user is currently connected."""
        return username.lower() in self.active_connections

    def get_online_users(self) -> List[str]:
        """Return list of lowercase usernames currently connected."""
        return list(self.active_connections.keys())

    async def send_to_user(self, username: str, message: dict) -> bool:
        """
        Send a JSON payload to a specific user.
        Returns True if delivered, False if user is offline or send failed.
        """
        key = username.lower()
        ws = self.active_connections.get(key)
        if ws:
            try:
                await ws.send_json(message)
                return True
            except Exception as e:
                logger.error(f"Error sending message to {username}: {e}")
                if key in self.active_connections:
                    del self.active_connections[key]
                return False
        return False

    async def broadcast(self, message: dict, exclude: Optional[str] = None) -> None:
        """Broadcast a JSON message to active connections, optionally excluding one user."""
        exclude_key = exclude.lower() if exclude else None
        stale_keys = []
        for uname, ws in list(self.active_connections.items()):
            if exclude_key and uname == exclude_key:
                continue
            try:
                await ws.send_json(message)
            except Exception:
                stale_keys.append(uname)

        for uname in stale_keys:
            if uname in self.active_connections:
                del self.active_connections[uname]

connection_manager = ConnectionManager()
