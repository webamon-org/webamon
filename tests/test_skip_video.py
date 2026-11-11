"""Video bodies are neither fetched nor stored unless save_video is on."""
import asyncio

from sandbox import capture
from sandbox.capture import is_video_mime


def test_is_video_mime():
    for m in ("video/mp4", "video/MP2T", "video/webm; codecs=vp9", "application/vnd.apple.mpegurl",
              "application/x-mpegURL", "application/dash+xml"):
        assert is_video_mime(m), m
    for m in ("application/javascript", "text/html", "image/png", "font/woff2", "", None, "application/json"):
        assert not is_video_mime(m), m


class FakeCDP:
    def __init__(self):
        self.asked = []

    async def send(self, method, params):
        self.asked.append(params["requestId"])
        return {"body": "x" + params["requestId"]}


class FakeNet:
    def __init__(self):
        self.requests = {
            "js": {"request": {"url": "https://a/x.js"}, "response": {"mimeType": "application/javascript"}},
            "mp4": {"request": {"url": "https://a/v.mp4"}, "response": {"mimeType": "video/mp4"}},
            "m3u8": {"request": {"url": "https://a/p.m3u8"}, "response": {"mimeType": "application/vnd.apple.mpegurl"}},
        }


def test_capture_skips_video_bodies_but_keeps_the_requests():
    cdp, net = FakeCDP(), FakeNet()
    snap, bodies = asyncio.run(capture.capture_bodies(cdp, net, skip_video=True))
    assert set(cdp.asked) == {"js"}
    assert set(bodies) == {"js"}
    assert set(snap) == {"js", "mp4", "m3u8"}          # network log still lists the video requests


def test_capture_fetches_video_when_enabled():
    cdp, net = FakeCDP(), FakeNet()
    _, bodies = asyncio.run(capture.capture_bodies(cdp, net, skip_video=False))
    assert set(bodies) == {"js", "mp4", "m3u8"}


def test_default_setting_is_off():
    from sandbox.config import Settings
    assert Settings().save_video is False
