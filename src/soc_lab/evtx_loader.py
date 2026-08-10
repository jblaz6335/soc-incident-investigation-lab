from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

from .models import SecurityEvent


def _text(element: ElementTree.Element | None, default: str = "") -> str:
    return element.text.strip() if element is not None and element.text else default


def parse_event_xml(xml_text: str) -> SecurityEvent:
    root = ElementTree.fromstring(xml_text)
    namespace = {"event": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("event:System", namespace)
    if system is None:
        raise ValueError("Windows event XML is missing the System element")

    event_data: dict[str, str] = {}
    for index, data in enumerate(root.findall("event:EventData/event:Data", namespace)):
        name = data.attrib.get("Name", f"Data{index}")
        event_data[name] = _text(data)

    event_id = _text(system.find("event:EventID", namespace))
    timestamp_node = system.find("event:TimeCreated", namespace)
    timestamp = timestamp_node.attrib.get("SystemTime", "") if timestamp_node is not None else ""
    if not timestamp:
        raise ValueError("Windows event XML is missing the event timestamp")

    outcome = ""
    if event_id == "4624":
        outcome = "success"
    elif event_id == "4625":
        outcome = "failure"

    destination_port = event_data.get("DestinationPort")
    payload = {
        "timestamp": timestamp,
        "event_id": event_id,
        "channel": _text(system.find("event:Channel", namespace)),
        "host": _text(system.find("event:Computer", namespace)),
        "username": event_data.get("TargetUserName") or event_data.get("User") or "",
        "source_ip": event_data.get("IpAddress") or event_data.get("SourceIp") or "",
        "destination_ip": event_data.get("DestinationIp", ""),
        "destination_port": int(destination_port) if destination_port and destination_port.isdigit() else None,
        "image": event_data.get("Image", ""),
        "command_line": event_data.get("CommandLine") or event_data.get("ScriptBlockText") or "",
        "target_path": event_data.get("ObjectName") or event_data.get("TargetFilename") or "",
        "action": event_data.get("AccessList") or event_data.get("GrantedAccess") or "",
        "outcome": outcome,
        "record_id": _text(system.find("event:EventRecordID", namespace)),
        "provider": (system.find("event:Provider", namespace).attrib.get("Name", "") if system.find("event:Provider", namespace) is not None else ""),
    }
    return SecurityEvent.from_mapping(payload)


def load_evtx_events(path: str | Path) -> list[SecurityEvent]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as error:
        raise RuntimeError(
            "EVTX support requires the optional dependency. Run: python -m pip install -e \".[evtx]\""
        ) from error

    source = Path(path)
    events: list[SecurityEvent] = []
    with Evtx(str(source)) as event_log:
        for record_number, record in enumerate(event_log.records(), start=1):
            try:
                events.append(parse_event_xml(record.xml()))
            except (ElementTree.ParseError, TypeError, ValueError) as error:
                raise ValueError(f"Invalid EVTX record {record_number}: {error}") from error
    return sorted(events, key=lambda event: event.timestamp)

