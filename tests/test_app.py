
import pytest

from app import app, is_allowed_pcap


@pytest.fixture
def client():
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


def test_dashboard_loads(client):
    response = client.get("/")
    assert response.status_code == 200


def test_history_page_loads(client):
    response = client.get("/history")
    assert response.status_code == 200


def test_alerts_page_loads(client):
    response = client.get("/alerts")
    assert response.status_code == 200


def test_ip_investigation_page_loads(client):
    response = client.get("/ip-investigation")
    assert response.status_code == 200


def test_valid_pcap_extensions():
    assert is_allowed_pcap("capture.pcap")
    assert is_allowed_pcap("capture.pcapng")
    assert is_allowed_pcap("CAPTURE.PCAP")


def test_invalid_file_extensions():
    assert not is_allowed_pcap("document.pdf")
    assert not is_allowed_pcap("script.py")
    assert not is_allowed_pcap("")
