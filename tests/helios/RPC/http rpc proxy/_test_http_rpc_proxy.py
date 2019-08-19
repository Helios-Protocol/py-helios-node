import asyncio
from random import randint
from eth_utils import to_hex
import aiohttp

#
# You must manually start the node before running these tests
#


url = 'http://127.0.0.1:30304'

async def _send_request_and_get_response(payload):
    print("SENDING PAYLOAD {}".format(payload))
    id = payload['id']
    async with aiohttp.ClientSession() as session:
        async with session.post(json=payload, url = url, timeout = 60*7) as resp:
            response = await resp.json()
            print(response)
            assert(response['id'] == id)


def _test_order_of_responses_async():
    #
    # Call a method that takes long, then call a short one after, and make sure each thread gets the correct response.
    #
    # {"jsonrpc": "2.0", "method": "hls_ping", "params": [], "id":1337}
    num_requests = 10
    payloads = []
    for i in range(num_requests):
        delay = to_hex(randint(0,5))
        payloads.append({"jsonrpc": "2.0", "method": 'dev_delayedResponse', "params":[delay], "id":i})

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(
        *[_send_request_and_get_response(payload) for payload in payloads]
    ))
    loop.close()

_test_order_of_responses_async()

# This runs for 6 minutes.
def _test_timeout():
    #
    # Call a method that takes long, then call a short one after, and make sure each thread gets the correct response.
    #
    # {"jsonrpc": "2.0", "method": "hls_ping", "params": [], "id":1337}

    payload = {"jsonrpc": "2.0", "method": 'dev_delayedResponse', "params":[60*6], "id":1}

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(
        _send_request_and_get_response(payload)
    ))
    loop.close()

#_test_timeout()






