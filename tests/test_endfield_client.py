"""Endfield protocol regressions: server roles, signed bytes and rewards."""

import httpx
import pytest

from core.skland import (
    Credential,
    EndfieldRole,
    SklandClient,
    SklandError,
    generate_signature,
)

CRED = Credential(token="tok", cred="cred")


def client_for(handler):
    client = SklandClient()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client._did = "Btest"
    return client


@pytest.mark.anyio
async def test_roles_use_role_and_server_ids_and_keep_multiple_servers():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "list": [
                        {"appCode": "arknights", "bindingList": [{"uid": "ark"}]},
                        {
                            "appCode": "endfield",
                            "bindingList": [
                                {
                                    "uid": "account-not-role",
                                    "channelMasterId": "not-server",
                                    "nickName": "fallback",
                                    "channelName": "官服",
                                    "roles": [
                                        {
                                            "roleId": "role1",
                                            "serverId": "srv1",
                                            "nickname": "one",
                                            "serverName": "一服",
                                        },
                                        {
                                            "roleId": "role1",
                                            "serverId": "srv2",
                                            "nickname": "two",
                                        },
                                        {"roleId": "role1", "serverId": "srv1"},
                                        {"roleId": "bad"},
                                    ],
                                }
                            ],
                        },
                    ]
                },
            },
        )

    client = client_for(handler)
    try:
        roles = await client.get_endfield_roles(CRED)
    finally:
        await client.close()
    assert [(r.role_id, r.server_id) for r in roles] == [
        ("role1", "srv1"),
        ("role1", "srv2"),
    ]
    assert roles[0].nickname == "one"
    assert roles[0].server_name == "一服"
    assert roles[1].server_name == "官服"


@pytest.mark.anyio
async def test_sign_sends_empty_signed_body_and_role_header():
    def handler(request):
        assert request.url.path == "/web/v1/game/endfield/attendance"
        assert request.method == "POST"
        assert request.content == b""
        assert request.headers["content-type"] == "application/json"
        assert request.headers["sk-game-role"] == "3_role1_srv1"
        assert request.headers["origin"] == "https://game.skland.com"
        signature, _ = generate_signature(
            "tok", request.url.path, "", "Btest", int(request.headers["timestamp"])
        )
        assert request.headers["sign"] == signature
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "awardIds": [{"id": "a"}, "b"],
                    "resourceInfoMap": {
                        "a": {"name": "嵌晶玉", "count": 100},
                        "b": {"name": "折金券", "count": 2},
                    },
                },
            },
        )

    client = client_for(handler)
    try:
        result = await client.sign_endfield(
            CRED, EndfieldRole("role1", "srv1", "admin")
        )
    finally:
        await client.close()
    assert result.success
    assert result.nickname == "admin"
    assert result.awards == ["嵌晶玉x100", "折金券x2"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload",
    [
        {"code": 10001, "message": "今日已签到"},
        {"code": 10002, "message": "活动尚未开始"},
    ],
)
async def test_business_rejection_is_a_normal_result(payload):
    client = client_for(lambda request: httpx.Response(200, json=payload))
    try:
        result = await client.sign_endfield(CRED, EndfieldRole("r", "s"))
    finally:
        await client.close()
    assert not result.success
    assert result.error == payload["message"]


@pytest.mark.anyio
async def test_http_error_keeps_upstream_reason():
    client = client_for(
        lambda request: httpx.Response(401, json={"message": "登录状态已失效"})
    )
    try:
        with pytest.raises(SklandError, match="登录状态已失效"):
            await client.sign_endfield(CRED, EndfieldRole("r", "s"))
    finally:
        await client.close()


@pytest.mark.anyio
async def test_incomplete_role_never_sends_a_request():
    def handler(request):
        pytest.fail("An incomplete server role must not reach the attendance API")

    client = client_for(handler)
    try:
        with pytest.raises(SklandError, match="不完整"):
            await client.sign_endfield(CRED, EndfieldRole("r", ""))
    finally:
        await client.close()
