from typing import Dict, Any, List
from pymodbus.client import ModbusTcpClient

def _validate_u16(name: str, value: int):
    if not isinstance(value, int) or not (0 <= value <= 0xFFFF):
        raise ValueError(f"{name} must be 0..65535 (got {value})")

def read_holding_registers(
    host: str,
    register: int,
    count: int = 1,
    unit: int = 1,
    port: int = 502,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Safe read of N holding registers (no write)."""
    _validate_u16("register", register)
    if not isinstance(count, int) or count <= 0 or count > 125:
        raise ValueError("count must be 1..125")

    client = ModbusTcpClient(host=host, port=port, timeout=timeout)
    if not client.connect():
        return {"ok": False, "error": "connect_failed", "host": host, "port": port}

    try:
        rr = client.read_holding_registers(register, count=count, slave=unit)
        if rr.isError():
            return {"ok": False, "error": str(rr)}
        values: List[int] = rr.registers or []
        return {
            "ok": True,
            "host": host,
            "port": port,
            "unit": unit,
            "start_register": register,
            "count": count,
            "values": values,
        }
    finally:
        client.close()

def write_holding_register(
    host: str,
    register: int,
    value: int,
    unit: int = 1,
    port: int = 502,
    timeout: float = 3.0,
    dry_run: bool = True,
    read_back: bool = False,
) -> Dict[str, Any]:
    # (unchanged from your current file)
    _validate_u16("register", register)
    _validate_u16("value", value)

    if dry_run:
        return {
            "dry_run": True,
            "action": "write_register",
            "host": host,
            "port": port,
            "unit": unit,
            "register": register,
            "value": value,
        }

    client = ModbusTcpClient(host=host, port=port, timeout=timeout)
    if not client.connect():
        return {"ok": False, "error": "connect_failed", "host": host, "port": port}
    try:
        wr = client.write_register(register, value, slave=unit)
        if hasattr(wr, "isError") and wr.isError():
            return {"ok": False, "error": str(wr)}
        result = {
            "ok": True,
            "host": host,
            "port": port,
            "unit": unit,
            "register": register,
            "written_value": value,
        }
        if read_back:
            rr = client.read_holding_registers(register, count=1, slave=unit)
            if rr.isError():
                result["read_back"] = {"ok": False, "error": str(rr)}
            else:
                rb_val = rr.registers[0] if rr.registers else None
                result["read_back"] = {"ok": True, "value": rb_val, "matches": (rb_val == value)}
        return result
    finally:
        client.close()

