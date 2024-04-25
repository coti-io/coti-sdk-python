import asyncio
import json

from dotenv import load_dotenv
from websockets import connect

from examples.basics.utils import get_node_wss_address


# Standard script utilizing websockets to notify when new header is appended to the chain
async def get_event():
    # Initiates the connection between your dapp and the network
    node_wss_address = get_node_wss_address()
    async with connect(node_wss_address) as ws:
        await ws.send(
            json.dumps({"id": 1, "jsonrpc": "2.0", "method": "eth_subscribe", "params": ["newHeads"]}))

        # Wait for the subscription completion.
        subscription_response = await ws.recv()
        print(f"Subscription response: {subscription_response}")
        # Connection has been successful, now it enters a loop where thanks to websocket's method recv(),
        # it waits for an event to be emitted.
        # If timeout reaches 60 seconds, it does not affect the connection, the program merely gets back to waiting.
        while True:
            try:
                # Wait for the message in websockets and print the contents.
                message = await asyncio.wait_for(ws.recv(), timeout=60)
                json_message = json.loads(message)
                result = json_message['params']['result']
                print(f"result: {result}")
            except asyncio.exceptions.TimeoutError:
                print("TimeoutError")
                pass


if __name__ == "__main__":
    load_dotenv()  # loading .env
    loop = asyncio.new_event_loop()
    loop.run_until_complete(get_event())
