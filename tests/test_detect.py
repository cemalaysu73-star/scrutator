import httpx
import respx

from scrutator.ai.detect import detect_local
from scrutator.ai.types import Runtime

OLLAMA = "http://127.0.0.1:11434/api/tags"
LMSTUDIO = "http://127.0.0.1:1234/v1/models"
LLAMACPP = "http://127.0.0.1:8080/v1/models"


def refuse(router, *urls):
    for url in urls:
        router.get(url).mock(side_effect=httpx.ConnectError("refused"))


async def test_finds_ollama_and_its_models(http):
    with respx.mock() as router:
        router.get(OLLAMA).mock(return_value=httpx.Response(200, json={"models": [{"name": "qwen3:8b"}, {"name": "llama3.2"}]}))
        refuse(router, LMSTUDIO, LLAMACPP)
        found = await detect_local(http)
    assert found == [Runtime("ollama", "http://127.0.0.1:11434", ("qwen3:8b", "llama3.2"))]


async def test_finds_openai_compatible_servers(http):
    with respx.mock() as router:
        refuse(router, OLLAMA)
        router.get(LMSTUDIO).mock(return_value=httpx.Response(200, json={"data": [{"id": "local-model"}]}))
        router.get(LLAMACPP).mock(return_value=httpx.Response(200, json={"data": []}))
        found = await detect_local(http)
    assert found == [
        Runtime("openai", "http://127.0.0.1:1234/v1", ("local-model",)),
        Runtime("openai", "http://127.0.0.1:8080/v1", ()),
    ]


async def test_nothing_running_and_garbage_replies_yield_nothing(http):
    with respx.mock() as router:
        refuse(router, OLLAMA, LMSTUDIO)
        router.get(LLAMACPP).mock(return_value=httpx.Response(200, text="<html>not an api</html>"))
        assert await detect_local(http) == []
