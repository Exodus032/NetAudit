from __future__ import annotations

from fastapi import APIRouter

from .. import netinfo

router = APIRouter()


@router.get("/api/interfaces")
def get_interfaces():
    interfaces = netinfo.list_interfaces()
    return {
        "interfaces": interfaces,
        "default_interface_id": netinfo.default_interface_id(interfaces),
    }
