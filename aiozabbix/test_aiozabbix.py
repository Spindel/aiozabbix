from aiohttp import web
import pytest

from aiozabbix import ZabbixAPI, ZabbixAPIException


async def mock_jsonrpc(request):
    request.app["requests"].append(request)

    request_json = await request.json()
    assert request_json["jsonrpc"] == "2.0"
    assert "params" in request_json
    assert "id" in request_json

    result = None

    method = request_json["method"]
    if ZabbixAPI.method_needs_auth(method):
        if not request.app["logged_in"]:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32602,
                        "message": "Invalid params.",
                        "data": "Not authorised.",
                    },
                    "id": request_json["id"],
                }
            )

    if method == "user.login":
        request.app["logged_in"] = True
        result = f"mock auth token {request.app['next_auth_token']}"
        request.app["next_auth_token"] += 1

    if result is None:
        result = f"mock response for {method}"

    return web.json_response(
        {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_json["id"],
        }
    )


@pytest.fixture
def mock_server_app():
    app = web.Application()
    app.router.add_post("/api_jsonrpc.php", mock_jsonrpc)
    app["requests"] = []
    app["logged_in"] = False
    app["next_auth_token"] = 1
    return app


@pytest.fixture
async def client_session(aiohttp_client, mock_server_app):
    return await aiohttp_client(mock_server_app)


@pytest.fixture
async def zapi(client_session, mock_server_app):
    return ZabbixAPI(server="", client_session=client_session)


async def test_unauthenticated_calls_should_work(mock_server_app, zapi):
    await zapi.apiinfo.version()

    requests = [await r.json() for r in mock_server_app["requests"]]
    assert len(requests) == 1
    assert requests[0]["method"] == "apiinfo.version"


async def test_authenticated_mock_calls_should_fail_before_login(zapi):
    with pytest.raises(ZabbixAPIException):
        await zapi.hostgroup.get()


async def test_login_should_work(mock_server_app, zapi):
    await zapi.login(user="Admin", password="zabbix")

    requests = [await r.json() for r in mock_server_app["requests"]]
    assert len(requests) == 1
    assert requests[0]["method"] == "user.login"
    assert requests[0]["params"] == {"user": "Admin", "password": "zabbix"}


async def test_authenticated_mock_calls_should_succeed_after_login(zapi):
    await zapi.login(user="Admin", password="zabbix")
    response = await zapi.hostgroup.get()
    assert "error" not in response


async def test_auth_token_should_be_sent(mock_server_app, zapi):
    await zapi.login(user="Admin", password="zabbix")
    await zapi.hostgroup.get()

    requests = [await r.json() for r in mock_server_app["requests"]]

    assert "auth" not in requests[0]
    assert requests[1]["auth"] == "mock auth token 1"


async def test_auth_error_should_cause_auto_relogin(mock_server_app, zapi):
    await zapi.login(user="Admin", password="zabbix")
    await zapi.hostgroup.get()

    mock_server_app["logged_in"] = False

    await zapi.hostgroup.get()

    requests = [await r.json() for r in mock_server_app["requests"]]
    assert len(requests) == 5
    assert requests[0]["method"] == "user.login"
    assert requests[1]["method"] == "hostgroup.get"
    # Second hostgroup.get that fails due to being logged out
    assert requests[2]["method"] == "hostgroup.get"
    assert requests[2]["auth"] == "mock auth token 1"
    # Auto login
    assert requests[3]["method"] == "user.login"
    # Retry of hostgroup.get
    assert requests[4]["method"] == "hostgroup.get"
    assert requests[4]["auth"] == "mock auth token 2"


async def test_import_underscore_attr_should_be_rewritten(mock_server_app, zapi):
    await zapi.login(user="Admin", password="zabbix")
    await zapi.confimport(
        confformat="xml", rules={}, source="<zabbix_export>...</zabbix_export>"
    )

    requests = [await r.json() for r in mock_server_app["requests"]]
    assert len(requests) == 2
    assert requests[1]["method"] == "configuration.import"
    assert requests[1]["params"] == {
        "format": "xml",
        "rules": {},
        "source": "<zabbix_export>...</zabbix_export>",
    }


async def test_custom_headers_should_be_sent(mock_server_app, client_session):
    zapi = ZabbixAPI(
        server="", client_session=client_session, headers={"User-Agent": "zabbixapp"}
    )

    await zapi.apiinfo.version()

    requests = mock_server_app["requests"]
    assert len(requests) == 1
    assert requests[0].headers["User-Agent"] == "zabbixapp"


async def test_zabbix_api_copies_should_share_state_correctly(mock_server_app, client_session):
    zapi = ZabbixAPI(
        server="", client_session=client_session, headers={"User-Agent": "zabbixapp"}
    )

    await zapi.apiinfo.version()

    zapi_with_extra_header = zapi.with_headers({"X-Extra-Header": "Yes"})
    await zapi_with_extra_header.apiinfo.version()

    await zapi.apiinfo.version()

    requests = mock_server_app["requests"]
    assert len(requests) == 3

    assert requests[0].headers["User-Agent"] == "zabbixapp"
    assert "X-Extra-Header" not in requests[0].headers

    assert requests[1].headers["User-Agent"] == "zabbixapp"
    assert requests[1].headers["X-Extra-Header"] == "Yes"

    assert requests[2].headers["User-Agent"] == "zabbixapp"
    assert "X-Extra-Header" not in requests[2].headers

    request_ids = [(await r.json())["id"] for r in mock_server_app["requests"]]
    assert request_ids == [0, 1, 2]


async def test_zabbix_api_object_copies_should_relogin_correctly(mock_server_app, zapi):
    await zapi.login(user="Admin", password="zabbix")
    await zapi.hostgroup.get()

    mock_server_app["logged_in"] = False
    zapi_with_extra_header = zapi.with_headers({"X-Extra-Header": "Yes"})

    await zapi_with_extra_header.hostgroup.get()

    requests = [await r.json() for r in mock_server_app["requests"]]
    assert len(requests) == 5
    assert requests[0]["method"] == "user.login"
    assert requests[1]["method"] == "hostgroup.get"
    # Second hostgroup.get that fails due to being logged out
    assert requests[2]["method"] == "hostgroup.get"
    assert requests[2]["auth"] == "mock auth token 1"
    # Auto login
    assert requests[3]["method"] == "user.login"
    # Retry of hostgroup.get
    assert requests[4]["method"] == "hostgroup.get"
    assert requests[4]["auth"] == "mock auth token 2"
