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
    fan_speed: str | None
    light_on: bool
    timer: str | None
    timer_remaining: str | None
    pre_filter_name: str
    pre_filter_pct: int
    pre_filter_last_changed: str
    pre_filter_change_months: str
    max2_name: str
    max2_pct: int
    max2_last_changed: str
    max2_change_months: str
    dust_pollution: str
    air_volume: str
    pollen_mode: str
    particulate_matter_2_5: str
    particulate_matter_10: str
    carbon_dioxide: str
    volatile_organic_compounds: str
    air_quality_index: str
