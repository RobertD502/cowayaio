"""Data classes for Coway IoCare Purifiers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PurifierData:
    """Dataclass for Purifier Data"""

    purifiers: dict[str, CowayPurifier]


@dataclass
class CowayPurifier:
    """Dataclass for Coway IoCare Purifier"""

    device_attr: dict[str, str]
    mcu_version: str | None
    network_status: bool
    is_on: bool
    auto_mode: bool
    auto_eco_mode: bool
    eco_mode: bool
    night_mode: bool
    rapid_mode: bool
    fan_speed: int | None
    light_on: bool
    light_mode: int
    button_lock: int | None
    timer: str | None
    timer_remaining: int | None
    pre_filter_pct: int
    max2_pct: int
    aq_grade: int
    particulate_matter_2_5: int | None
    particulate_matter_10: int | None
    carbon_dioxide: int | None
    volatile_organic_compounds: int | None
    air_quality_index: int | None
    lux_sensor: int | None
    pre_filter_change_frequency: int
    smart_mode_sensitivity: int
