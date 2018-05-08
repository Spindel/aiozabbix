aiozabbix
=========

**aiozabbix** is a Python package that provides an asynchronous
interface to the
[Zabbix API](https://www.zabbix.com/documentation/3.0/manual/api/reference),
using aiohttp. It is based on
[PyZabbix](https://github.com/lukecyca/pyzabbix).

Example usage
-------------

The interface mimics PyZabbix as closely as possible:

```python
import asyncio

from aiozabbix import ZabbixAPI


async def main():
    zapi = ZabbixAPI('https://zabbixserver.example.com/zabbix')
    await zapi.login('zabbix user')
    hosts = await zapi.host.get(output=['host', 'hostid', 'name', 'status'])
    print(hosts)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
```

To customize the HTTP requests, for example to perform HTTP basic
authentication, you need to provide your own `aiohttp.ClientSession`:

```python
import asyncio

import aiohttp
from aiozabbix import ZabbixAPI


async def main():
    auth = aiohttp.BasicAuth('zabbix user', password='zabbix password')
    async with aiohttp.ClientSession(auth=auth) as session:
        zapi = ZabbixAPI('https://zabbixserver.example.com/zabbix', client_session=session)
        await zapi.login('zabbix user')
        hosts = await zapi.host.get(output=['host', 'hostid', 'name', 'status'])
        print(hosts)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
```
