"""Data classes for Coway IoCare Purifiers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PurifierData:
    """Dataclass for Purifier Data"""

    purifiers: dict[str, CowayPurifier]


@dataclass
class CowayPurifier:
    """Dataclass for Coway IoCare Purifier"""

    device_attr: dict[str, Any]
    mcu_version: str | None
    network_status: bool | None
    is_on: bool | None
    auto_mode: bool | None
    auto_eco_mode: bool | None
    eco_mode: bool | None
    night_mode: bool | None
    rapid_mode: bool | None
    fan_speed: int | None
    light_on: bool | None
    light_mode: int | None
    button_lock: int | None
    timer: str | None
    timer_remaining: int | None
    pre_filter_pct: int | None
    max2_pct: int | None
    aq_grade: int | None
    particulate_matter_2_5: int | None
    particulate_matter_10: int | None
    carbon_dioxide: int | None
    volatile_organic_compounds: int | None
    air_quality_index: int | None
    lux_sensor: int | None
    pre_filter_change_frequency: int | None
    smart_mode_sensitivity: int | None
