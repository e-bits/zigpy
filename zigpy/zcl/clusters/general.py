"""General Functional Domain"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import logging
import time

from Crypto.Cipher import AES
from Crypto.Util import Counter

import zigpy
import zigpy.types as t
import zigpy.zdo as zdo
from zigpy.typing import AddressingMode
from zigpy.zcl import Cluster, foundation
from zigpy.zcl.foundation import ZCLAttributeDef, ZCLCommandDef

LOGGER = logging.getLogger(__name__)


class Basic(Cluster):
    """Attributes for determining basic information about a
    device, setting user device information such as location,
    and enabling a device.
    """

    class PowerSource(t.enum8):
        """Power source enum."""

        Unknown = 0x00
        Mains_single_phase = 0x01
        Mains_three_phase = 0x02
        Battery = 0x03
        DC_Source = 0x04
        Emergency_Mains_Always_On = 0x05
        Emergency_Mains_Transfer_Switch = 0x06

        def __init__(self, *args, **kwargs):
            self.battery_backup = False

        @classmethod
        def deserialize(cls, data: bytes) -> tuple[bytes, bytes]:
            val, data = t.uint8_t.deserialize(data)
            r = cls(val & 0x7F)
            r.battery_backup = bool(val & 0x80)
            return r, data

    class PhysicalEnvironment(t.enum8):
        Unspecified_environment = 0x00
        # Mirror Capacity Available: for 0x0109 Profile Id only; use 0x71 moving forward
        # Atrium: defined for legacy devices with non-0x0109 Profile Id; use 0x70 moving
        #         forward

        # Note: This value is deprecated for Profile Id 0x0104. The value 0x01 is
        #       maintained for historical purposes and SHOULD only be used for backwards
        #       compatibility with devices developed before this specification. The 0x01
        #       value MUST be interpreted using the Profile Id of the endpoint upon
        #       which it is implemented. For endpoints with the Smart Energy Profile Id
        #       (0x0109) the value 0x01 has a meaning of Mirror. For endpoints with any
        #       other profile identifier, the value 0x01 has a meaning of Atrium.
        Mirror_or_atrium_legacy = 0x01
        Bar = 0x02
        Courtyard = 0x03
        Bathroom = 0x04
        Bedroom = 0x05
        Billiard_Room = 0x06
        Utility_Room = 0x07
        Cellar = 0x08
        Storage_Closet = 0x09
        Theater = 0x0A
        Office = 0x0B
        Deck = 0x0C
        Den = 0x0D
        Dining_Room = 0x0E
        Electrical_Room = 0x0F
        Elevator = 0x10
        Entry = 0x11
        Family_Room = 0x12
        Main_Floor = 0x13
        Upstairs = 0x14
        Downstairs = 0x15
        Basement = 0x16
        Gallery = 0x17
        Game_Room = 0x18
        Garage = 0x19
        Gym = 0x1A
        Hallway = 0x1B
        House = 0x1C
        Kitchen = 0x1D
        Laundry_Room = 0x1E
        Library = 0x1F
        Master_Bedroom = 0x20
        Mud_Room_small_room_for_coats_and_boots = 0x21
        Nursery = 0x22
        Pantry = 0x23
        Office_2 = 0x24
        Outside = 0x25
        Pool = 0x26
        Porch = 0x27
        Sewing_Room = 0x28
        Sitting_Room = 0x29
        Stairway = 0x2A
        Yard = 0x2B
        Attic = 0x2C
        Hot_Tub = 0x2D
        Living_Room = 0x2E
        Sauna = 0x2F
        Workshop = 0x30
        Guest_Bedroom = 0x31
        Guest_Bath = 0x32
        Back_Yard = 0x34
        Front_Yard = 0x35
        Patio = 0x36
        Driveway = 0x37
        Sun_Room = 0x38
        Grand_Room = 0x39
        Spa = 0x3A
        Whirlpool = 0x3B
        Shed = 0x3C
        Equipment_Storage = 0x3D
        Craft_Room = 0x3E
        Fountain = 0x3F
        Pond = 0x40
        Reception_Room = 0x41
        Breakfast_Room = 0x42
        Nook = 0x43
        Garden = 0x44
        Balcony = 0x45
        Panic_Room = 0x46
        Terrace = 0x47
        Roof = 0x48
        Toilet = 0x49
        Toilet_Main = 0x4A
        Outside_Toilet = 0x4B
        Shower_room = 0x4C
        Study = 0x4D
        Front_Garden = 0x4E
        Back_Garden = 0x4F
        Kettle = 0x50
        Television = 0x51
        Stove = 0x52
        Microwave = 0x53
        Toaster = 0x54
        Vacuum = 0x55
        Appliance = 0x56
        Front_Door = 0x57
        Back_Door = 0x58
        Fridge_Door = 0x59
        Medication_Cabinet_Door = 0x60
        Wardrobe_Door = 0x61
        Front_Cupboard_Door = 0x62
        Other_Door = 0x63
        Waiting_Room = 0x64
        Triage_Room = 0x65
        Doctors_Office = 0x66
        Patients_Private_Room = 0x67
        Consultation_Room = 0x68
        Nurse_Station = 0x69
        Ward = 0x6A
        Corridor = 0x6B
        Operating_Theatre = 0x6C
        Dental_Surgery_Room = 0x6D
        Medical_Imaging_Room = 0x6E
        Decontamination_Room = 0x6F
        Atrium = 0x70
        Mirror = 0x71
        Unknown_environment = 0xFF

    class AlarmMask(t.bitmap8):
        General_hardware_fault = 0x01
        General_software_fault = 0x02

    class DisableLocalConfig(t.bitmap8):
        Reset = 0x01
        Device_Configuration = 0x02

    class GenericDeviceClass(t.enum8):
        Lighting = 0x00

    class GenericLightingDeviceType(t.enum8):
        Incandescent = 0x00
        Spotlight_Halogen = 0x01
        Halogen_bulb = 0x02
        CFL = 0x03
        Linear_Fluorescent = 0x04
        LED_bulb = 0x05
        Spotlight_LED = 0x06
        LED_strip = 0x07
        LED_tube = 0x08
        Generic_indoor_luminaire = 0x09
        Generic_outdoor_luminaire = 0x0A
        Pendant_luminaire = 0x0B
        Floor_standing_luminaire = 0x0C
        Generic_Controller = 0xE0
        Wall_Switch = 0xE1
        Portable_remote_controller = 0xE2
        Motion_sensor = 0xE3
        # 0xe4 to 0xef Reserved
        Generic_actuator = 0xF0
        Wall_socket = 0xF1
        Gateway_Bridge = 0xF2
        Plug_in_unit = 0xF3
        Retrofit_actuator = 0xF4
        Unspecified = 0xFF

    cluster_id = 0x0000
    ep_attribute = "basic"
    attributes: dict[int, ZCLAttributeDef] = {
        # Basic Device Information
        0x0000: ZCLAttributeDef(
            "zcl_version", type=t.uint8_t, access="r", mandatory=True
        ),
        0x0001: ZCLAttributeDef("app_version", type=t.uint8_t, access="r"),
        0x0002: ZCLAttributeDef("stack_version", type=t.uint8_t, access="r"),
        0x0003: ZCLAttributeDef("hw_version", type=t.uint8_t, access="r"),
        0x0004: ZCLAttributeDef(
            "manufacturer", type=t.LimitedCharString(32), access="r"
        ),
        0x0005: ZCLAttributeDef("model", type=t.LimitedCharString(32), access="r"),
        0x0006: ZCLAttributeDef("date_code", type=t.LimitedCharString(16), access="r"),
        0x0007: ZCLAttributeDef(
            "power_source", type=PowerSource, access="r", mandatory=True
        ),
        0x0008: ZCLAttributeDef(
            "generic_device_class", type=GenericDeviceClass, access="r"
        ),
        # Lighting is the only non-reserved device type
        0x0009: ZCLAttributeDef(
            "generic_device_type", type=GenericLightingDeviceType, access="r"
        ),
        0x000A: ZCLAttributeDef("product_code", type=t.LVBytes, access="r"),
        0x000B: ZCLAttributeDef("product_url", type=t.CharacterString, access="r"),
        0x000C: ZCLAttributeDef(
            "manufacturer_version_details", type=t.CharacterString, access="r"
        ),
        0x000D: ZCLAttributeDef("serial_number", type=t.CharacterString, access="r"),
        0x000E: ZCLAttributeDef("product_label", type=t.CharacterString, access="r"),
        # Basic Device Settings
        0x0010: ZCLAttributeDef(
            "location_desc", type=t.LimitedCharString(16), access="rw"
        ),
        0x0011: ZCLAttributeDef("physical_env", type=PhysicalEnvironment, access="rw"),
        0x0012: ZCLAttributeDef("device_enabled", type=t.Bool, access="rw"),
        0x0013: ZCLAttributeDef("alarm_mask", type=AlarmMask, access="rw"),
        0x0014: ZCLAttributeDef(
            "disable_local_config", type=DisableLocalConfig, access="rw"
        ),
        0x4000: ZCLAttributeDef("sw_build_id", type=t.CharacterString, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef("reset_fact_default", {}, False)
    }
    client_commands: dict[int, ZCLCommandDef] = {}


class PowerConfiguration(Cluster):
    """Attributes for determining more detailed information
    about a device’s power source(s), and for configuring
    under/over voltage alarms."""

    class MainsAlarmMask(t.bitmap8):
        Voltage_Too_Low = 0b00000001
        Voltage_Too_High = 0b00000010
        Power_Supply_Unavailable = 0b00000100

    class BatterySize(t.enum8):
        No_battery = 0x00
        Built_in = 0x01
        Other = 0x02
        AA = 0x03
        AAA = 0x04
        C = 0x05
        D = 0x06
        CR2 = 0x07
        CR123A = 0x08
        Unknown = 0xFF

    cluster_id = 0x0001
    name = "Power Configuration"
    ep_attribute = "power"
    attributes: dict[int, ZCLAttributeDef] = {
        # Mains Information
        0x0000: ZCLAttributeDef("mains_voltage", type=t.uint16_t, access="r"),
        0x0001: ZCLAttributeDef("mains_frequency", type=t.uint8_t, access="r"),
        # Mains Settings
        0x0010: ZCLAttributeDef("mains_alarm_mask", type=MainsAlarmMask, access="rw"),
        0x0011: ZCLAttributeDef("mains_volt_min_thres", type=t.uint16_t, access="rw"),
        0x0012: ZCLAttributeDef("mains_volt_max_thres", type=t.uint16_t, access="rw"),
        0x0013: ZCLAttributeDef(
            "mains_voltage_dwell_trip_point", type=t.uint16_t, access="rw"
        ),
        # Battery Information
        0x0020: ZCLAttributeDef("battery_voltage", type=t.uint8_t, access="r"),
        0x0021: ZCLAttributeDef(
            "battery_percentage_remaining", type=t.uint8_t, access="rp"
        ),
        # Battery Settings
        0x0030: ZCLAttributeDef(
            "battery_manufacturer", type=t.LimitedCharString(16), access="rw"
        ),
        0x0031: ZCLAttributeDef("battery_size", type=BatterySize, access="rw"),
        0x0032: ZCLAttributeDef(
            "battery_a_hr_rating", type=t.uint16_t, access="rw"
        ),  # measured in units of 10mAHr
        0x0033: ZCLAttributeDef("battery_quantity", type=t.uint8_t, access="rw"),
        0x0034: ZCLAttributeDef(
            "battery_rated_voltage", type=t.uint8_t, access="rw"
        ),  # measured in units of 100mV
        0x0035: ZCLAttributeDef("battery_alarm_mask", type=t.bitmap8, access="rw"),
        0x0036: ZCLAttributeDef("battery_volt_min_thres", type=t.uint8_t, access="rw"),
        0x0037: ZCLAttributeDef("battery_volt_thres1", type=t.uint16_t, access="r*w"),
        0x0038: ZCLAttributeDef("battery_volt_thres2", type=t.uint16_t, access="r*w"),
        0x0039: ZCLAttributeDef("battery_volt_thres3", type=t.uint16_t, access="r*w"),
        0x003A: ZCLAttributeDef(
            "battery_percent_min_thres", type=t.uint8_t, access="r*w"
        ),
        0x003B: ZCLAttributeDef("battery_percent_thres1", type=t.uint8_t, access="r*w"),
        0x003C: ZCLAttributeDef("battery_percent_thres2", type=t.uint8_t, access="r*w"),
        0x003D: ZCLAttributeDef("battery_percent_thres3", type=t.uint8_t, access="r*w"),
        0x003E: ZCLAttributeDef("battery_alarm_state", type=t.bitmap32, access="rp"),
        # Battery 2 Information
        0x0040: ZCLAttributeDef("battery_2_voltage", type=t.uint8_t, access="r"),
        0x0041: ZCLAttributeDef(
            "battery_2_percentage_remaining", type=t.uint8_t, access="rp"
        ),
        # Battery 2 Settings
        0x0050: ZCLAttributeDef(
            "battery_2_manufacturer", type=t.CharacterString, access="rw"
        ),
        0x0051: ZCLAttributeDef("battery_2_size", type=BatterySize, access="rw"),
        0x0052: ZCLAttributeDef("battery_2_a_hr_rating", type=t.uint16_t, access="rw"),
        0x0053: ZCLAttributeDef("battery_2_quantity", type=t.uint8_t, access="rw"),
        0x0054: ZCLAttributeDef("battery_2_rated_voltage", type=t.uint8_t, access="rw"),
        0x0055: ZCLAttributeDef("battery_2_alarm_mask", type=t.bitmap8, access="rw"),
        0x0056: ZCLAttributeDef(
            "battery_2_volt_min_thres", type=t.uint8_t, access="rw"
        ),
        0x0057: ZCLAttributeDef("battery_2_volt_thres1", type=t.uint16_t, access="r*w"),
        0x0058: ZCLAttributeDef("battery_2_volt_thres2", type=t.uint16_t, access="r*w"),
        0x0059: ZCLAttributeDef("battery_2_volt_thres3", type=t.uint16_t, access="r*w"),
        0x005A: ZCLAttributeDef(
            "battery_2_percent_min_thres", type=t.uint8_t, access="r*w"
        ),
        0x005B: ZCLAttributeDef(
            "battery_2_percent_thres1", type=t.uint8_t, access="r*w"
        ),
        0x005C: ZCLAttributeDef(
            "battery_2_percent_thres2", type=t.uint8_t, access="r*w"
        ),
        0x005D: ZCLAttributeDef(
            "battery_2_percent_thres3", type=t.uint8_t, access="r*w"
        ),
        0x005E: ZCLAttributeDef("battery_2_alarm_state", type=t.bitmap32, access="rp"),
        # Battery 3 Information
        0x0060: ZCLAttributeDef("battery_3_voltage", type=t.uint8_t, access="r"),
        0x0061: ZCLAttributeDef(
            "battery_3_percentage_remaining", type=t.uint8_t, access="rp"
        ),
        # Battery 3 Settings
        0x0070: ZCLAttributeDef(
            "battery_3_manufacturer", type=t.CharacterString, access="rw"
        ),
        0x0071: ZCLAttributeDef("battery_3_size", type=BatterySize, access="rw"),
        0x0072: ZCLAttributeDef("battery_3_a_hr_rating", type=t.uint16_t, access="rw"),
        0x0073: ZCLAttributeDef("battery_3_quantity", type=t.uint8_t, access="rw"),
        0x0074: ZCLAttributeDef("battery_3_rated_voltage", type=t.uint8_t, access="rw"),
        0x0075: ZCLAttributeDef("battery_3_alarm_mask", type=t.bitmap8, access="rw"),
        0x0076: ZCLAttributeDef(
            "battery_3_volt_min_thres", type=t.uint8_t, access="rw"
        ),
        0x0077: ZCLAttributeDef("battery_3_volt_thres1", type=t.uint16_t, access="r*w"),
        0x0078: ZCLAttributeDef("battery_3_volt_thres2", type=t.uint16_t, access="r*w"),
        0x0079: ZCLAttributeDef("battery_3_volt_thres3", type=t.uint16_t, access="r*w"),
        0x007A: ZCLAttributeDef(
            "battery_3_percent_min_thres", type=t.uint8_t, access="r*w"
        ),
        0x007B: ZCLAttributeDef(
            "battery_3_percent_thres1", type=t.uint8_t, access="r*w"
        ),
        0x007C: ZCLAttributeDef(
            "battery_3_percent_thres2", type=t.uint8_t, access="r*w"
        ),
        0x007D: ZCLAttributeDef(
            "battery_3_percent_thres3", type=t.uint8_t, access="r*w"
        ),
        0x007E: ZCLAttributeDef("battery_3_alarm_state", type=t.bitmap32, access="rp"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class DeviceTemperature(Cluster):
    """Attributes for determining information about a device’s
    internal temperature, and for configuring under/over
    temperature alarms."""

    class DeviceTempAlarmMask(t.bitmap8):
        Temp_too_low = 0b00000001
        Temp_too_high = 0b00000010

    cluster_id = 0x0002
    name = "Device Temperature"
    ep_attribute = "device_temperature"
    attributes: dict[int, ZCLAttributeDef] = {
        # Device Temperature Information
        0x0000: ZCLAttributeDef(
            "current_temperature", type=t.int16s, access="r", mandatory=True
        ),
        0x0001: ZCLAttributeDef("min_temp_experienced", type=t.int16s, access="r"),
        0x0002: ZCLAttributeDef("max_temp_experienced", type=t.int16s, access="r"),
        0x0003: ZCLAttributeDef("over_temp_total_dwell", type=t.uint16_t, access="r"),
        # Device Temperature Settings
        0x0010: ZCLAttributeDef(
            "dev_temp_alarm_mask", type=DeviceTempAlarmMask, access="rw"
        ),
        0x0011: ZCLAttributeDef("low_temp_thres", type=t.int16s, access="rw"),
        0x0012: ZCLAttributeDef("high_temp_thres", type=t.int16s, access="rw"),
        0x0013: ZCLAttributeDef(
            "low_temp_dwell_trip_point", type=t.uint24_t, access="rw"
        ),
        0x0014: ZCLAttributeDef(
            "high_temp_dwell_trip_point", type=t.uint24_t, access="rw"
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class Identify(Cluster):
    """Attributes and commands for putting a device into
    Identification mode (e.g. flashing a light)"""

    class EffectIdentifier(t.enum8):
        Blink = 0x00
        Breathe = 0x01
        Okay = 0x02
        Channel_change = 0x03
        Finish_effect = 0xFE
        Stop_effect = 0xFF

    class EffectVariant(t.enum8):
        Default = 0x00

    cluster_id = 0x0003
    ep_attribute = "identify"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "identify_time", type=t.uint16_t, access="rw", mandatory=True
        ),
        # 0x0001: ZCLAttributeDef("identify_commission_state", type=t.bitmap8),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef("identify", {"identify_time": t.uint16_t}, False),
        0x01: ZCLCommandDef("identify_query", {}, False),
        # 0x02: ("ezmode_invoke", (t.bitmap8,), False),
        # 0x03: ("update_commission_state", (t.bitmap8,), False),
        0x40: ZCLCommandDef(
            "trigger_effect",
            {"effect_id": EffectIdentifier, "effect_variant": EffectVariant},
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef("identify_query_response", {"timeout": t.uint16_t}, True)
    }


class Groups(Cluster):
    """Attributes and commands for group configuration and
    manipulation."""

    class NameSupport(t.bitmap8):
        Supported = 0b10000000

    cluster_id = 0x0004
    ep_attribute = "groups"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "name_support", type=NameSupport, access="r", mandatory=True
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "add",
            {"group_id": t.Group, "group_name": t.LimitedCharString(16)},
            False,
        ),
        0x01: ZCLCommandDef("view", {"group_id": t.Group}, False),
        0x02: ZCLCommandDef("get_membership", {"groups": t.LVList[t.Group]}, False),
        0x03: ZCLCommandDef("remove", {"group_id": t.Group}, False),
        0x04: ZCLCommandDef("remove_all", {}, False),
        0x05: ZCLCommandDef(
            "add_if_identifying",
            {"group_id": t.Group, "group_name": t.LimitedCharString(16)},
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "add_response",
            {"status": foundation.Status, "group_id": t.Group},
            True,
        ),
        0x01: ZCLCommandDef(
            "view_response",
            {
                "status": foundation.Status,
                "group_id": t.Group,
                "group_name": t.LimitedCharString(16),
            },
            True,
        ),
        0x02: ZCLCommandDef(
            "get_membership_response",
            {"capacity": t.uint8_t, "groups": t.LVList[t.Group]},
            True,
        ),
        0x03: ZCLCommandDef(
            "remove_response",
            {"status": foundation.Status, "group_id": t.Group},
            True,
        ),
    }


class Scenes(Cluster):
    """Attributes and commands for scene configuration and
    manipulation."""

    class NameSupport(t.bitmap8):
        Supported = 0b10000000

    cluster_id = 0x0005
    ep_attribute = "scenes"
    attributes: dict[int, ZCLAttributeDef] = {
        # Scene Management Information
        0x0000: ZCLAttributeDef("count", type=t.uint8_t, access="r", mandatory=True),
        0x0001: ZCLAttributeDef(
            "current_scene", type=t.uint8_t, access="r", mandatory=True
        ),
        0x0002: ZCLAttributeDef(
            "current_group", type=t.uint16_t, access="r", mandatory=True
        ),
        0x0003: ZCLAttributeDef("scene_valid", type=t.Bool, access="r", mandatory=True),
        0x0004: ZCLAttributeDef(
            "name_support", type=NameSupport, access="r", mandatory=True
        ),
        0x0005: ZCLAttributeDef("last_configured_by", type=t.EUI64, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "add",
            {
                "group_id": t.Group,
                "scene_id": t.uint8_t,
                "transition_time": t.uint16_t,
                "scene_name": t.LimitedCharString(16),
            },
            False,
        ),  # TODO: + extension field sets
        0x01: ZCLCommandDef(
            "view", {"group_id": t.Group, "scene_id": t.uint8_t}, False
        ),
        0x02: ZCLCommandDef(
            "remove", {"group_id": t.Group, "scene_id": t.uint8_t}, False
        ),
        0x03: ZCLCommandDef("remove_all", {"group_id": t.Group}, False),
        0x04: ZCLCommandDef(
            "store", {"group_id": t.Group, "scene_id": t.uint8_t}, False
        ),
        0x05: ZCLCommandDef(
            "recall",
            {
                "group_id": t.Group,
                "scene_id": t.uint8_t,
                "transition_time?": t.uint16_t,
            },
            False,
        ),
        0x06: ZCLCommandDef("get_scene_membership", {"group_id": t.Group}, False),
        0x40: ZCLCommandDef(
            "enhanced_add",
            {
                "group_id": t.Group,
                "scene_id": t.uint8_t,
                "transition_time": t.uint16_t,
                "scene_name": t.LimitedCharString(16),
            },
            False,
        ),
        0x41: ZCLCommandDef(
            "enhanced_view", {"group_id": t.Group, "scene_id": t.uint8_t}, False
        ),
        0x42: ZCLCommandDef(
            "copy",
            {
                "mode": t.uint8_t,
                "group_id_from": t.uint16_t,
                "scene_id_from": t.uint8_t,
                "group_id_to": t.uint16_t,
                "scene_id_to": t.uint8_t,
            },
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "add_scene_response",
            {"status": foundation.Status, "group_id": t.Group, "scene_id": t.uint8_t},
            True,
        ),
        0x01: ZCLCommandDef(
            "view_response",
            {
                "status": foundation.Status,
                "group_id": t.Group,
                "scene_id": t.uint8_t,
                "transition_time?": t.uint16_t,
                "scene_name?": t.LimitedCharString(16),
            },
            True,
        ),  # TODO: + extension field sets
        0x02: ZCLCommandDef(
            "remove_scene_response",
            {"status": foundation.Status, "group_id": t.Group, "scene_id": t.uint8_t},
            True,
        ),
        0x03: ZCLCommandDef(
            "remove_all_scenes_response",
            {"status": foundation.Status, "group_id": t.Group},
            True,
        ),
        0x04: ZCLCommandDef(
            "store_scene_response",
            {"status": foundation.Status, "group_id": t.Group, "scene_id": t.uint8_t},
            True,
        ),
        0x06: ZCLCommandDef(
            "get_scene_membership_response",
            {
                "status": foundation.Status,
                "capacity": t.uint8_t,
                "group_id": t.Group,
                "scenes?": t.LVList[t.uint8_t],
            },
            True,
        ),
        0x40: ZCLCommandDef(
            "enhanced_add_response",
            {"status": foundation.Status, "group_id": t.Group, "scene_id": t.uint8_t},
            True,
        ),
        0x41: ZCLCommandDef(
            "enhanced_view_response",
            {
                "status": foundation.Status,
                "group_id": t.Group,
                "scene_id": t.uint8_t,
                "transition_time?": t.uint16_t,
                "scene_name?": t.LimitedCharString(16),
            },
            True,
        ),  # TODO: + extension field sets
        0x42: ZCLCommandDef(
            "copy_response",
            {"status": foundation.Status, "group_id": t.Group, "scene_id": t.uint8_t},
            True,
        ),
    }


class OnOff(Cluster):
    """Attributes and commands for switching devices between
    ‘On’ and ‘Off’ states."""

    class StartUpOnOff(t.enum8):
        Off = 0x00
        On = 0x01
        Toggle = 0x02
        PreviousValue = 0xFF

    class OffEffectIdentifier(t.enum8):
        Delayed_All_Off = 0x00
        Dying_Light = 0x01

    class OnOffControl(t.bitmap8):
        Accept_Only_When_On = 0b00000001

    DELAYED_ALL_OFF_FADE_TO_OFF = 0x00
    DELAYED_ALL_OFF_NO_FADE = 0x01
    DELAYED_ALL_OFF_DIM_THEN_FADE_TO_OFF = 0x02

    DYING_LIGHT_DIM_UP_THEN_FADE_TO_OFF = 0x00

    cluster_id = 0x0006
    name = "On/Off"
    ep_attribute = "on_off"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef("on_off", type=t.Bool, access="rps", mandatory=True),
        0x4000: ZCLAttributeDef("global_scene_control", type=t.Bool, access="r"),
        0x4001: ZCLAttributeDef("on_time", type=t.uint16_t, access="rw"),
        0x4002: ZCLAttributeDef("off_wait_time", type=t.uint16_t, access="rw"),
        0x4003: ZCLAttributeDef("start_up_on_off", type=StartUpOnOff, access="rw"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef("off", {}, False),
        0x01: ZCLCommandDef("on", {}, False),
        0x02: ZCLCommandDef("toggle", {}, False),
        0x40: ZCLCommandDef(
            "off_with_effect",
            {"effect_id": OffEffectIdentifier, "effect_variant": t.uint8_t},
            False,
        ),
        0x41: ZCLCommandDef("on_with_recall_global_scene", {}, False),
        0x42: ZCLCommandDef(
            "on_with_timed_off",
            {
                "on_off_control": OnOffControl,
                "on_time": t.uint16_t,
                "off_wait_time": t.uint16_t,
            },
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {}


class OnOffConfiguration(Cluster):
    """Attributes and commands for configuring On/Off switching devices"""

    class SwitchType(t.enum8):
        Toggle = 0x00
        Momentary = 0x01
        Multifunction = 0x02

    class SwitchActions(t.enum8):
        OnOff = 0x00
        OffOn = 0x01
        ToggleToggle = 0x02

    cluster_id = 0x0007
    name = "On/Off Switch Configuration"
    ep_attribute = "on_off_config"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "switch_type", type=SwitchType, access="r", mandatory=True
        ),
        0x0010: ZCLAttributeDef(
            "switch_actions", type=SwitchActions, access="rw", mandatory=True
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class LevelControl(Cluster):
    """Attributes and commands for controlling devices that
    can be set to a level between fully ‘On’ and fully ‘Off’."""

    class MoveMode(t.enum8):
        Up = 0x00
        Down = 0x01

    class StepMode(t.enum8):
        Up = 0x00
        Down = 0x01

    class Options(t.bitmap8):
        Execute_if_off = 0b00000001
        Couple_color_temp_to_level = 0b00000010

    cluster_id = 0x0008
    name = "Level control"
    ep_attribute = "level"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "current_level", type=t.uint8_t, access="rps", mandatory=True
        ),
        0x0001: ZCLAttributeDef("remaining_time", type=t.uint16_t, access="r"),
        0x0002: ZCLAttributeDef("min_level", type=t.uint8_t, access="r"),
        0x0003: ZCLAttributeDef("max_level", type=t.uint8_t, access="r"),
        0x0004: ZCLAttributeDef("current_frequency", type=t.uint16_t, access="rps"),
        0x0005: ZCLAttributeDef("min_frequency", type=t.uint16_t, access="r"),
        0x0006: ZCLAttributeDef("max_frequency", type=t.uint16_t, access="r"),
        0x000F: ZCLAttributeDef("options", type=t.bitmap8, access="rw"),
        0x0010: ZCLAttributeDef("on_off_transition_time", type=t.uint16_t, access="rw"),
        0x0011: ZCLAttributeDef("on_level", type=t.uint8_t, access="rw"),
        0x0012: ZCLAttributeDef("on_transition_time", type=t.uint16_t, access="rw"),
        0x0013: ZCLAttributeDef("off_transition_time", type=t.uint16_t, access="rw"),
        0x0014: ZCLAttributeDef("default_move_rate", type=t.uint8_t, access="rw"),
        0x4000: ZCLAttributeDef("start_up_current_level", type=t.uint8_t, access="rw"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "move_to_level",
            {
                "level": t.uint8_t,
                "transition_time": t.uint16_t,
                "options_mask?": t.bitmap8,
                "options_override?": t.bitmap8,
            },
            False,
        ),
        0x01: ZCLCommandDef(
            "move",
            {
                "move_mode": MoveMode,
                "rate": t.uint8_t,
                "options_mask?": t.bitmap8,
                "options_override?": t.bitmap8,
            },
            False,
        ),
        0x02: ZCLCommandDef(
            "step",
            {
                "step_mode": StepMode,
                "step_size": t.uint8_t,
                "transition_time": t.uint16_t,
                "options_mask?": t.bitmap8,
                "options_override?": t.bitmap8,
            },
            False,
        ),
        0x03: ZCLCommandDef(
            "stop",
            {
                "options_mask?": t.bitmap8,
                "options_override?": t.bitmap8,
            },
            False,
        ),
        0x04: ZCLCommandDef(
            "move_to_level_with_on_off",
            {"level": t.uint8_t, "transition_time": t.uint16_t},
            False,
        ),
        0x05: ZCLCommandDef(
            "move_with_on_off", {"move_mode": MoveMode, "rate": t.uint8_t}, False
        ),
        0x06: ZCLCommandDef(
            "step_with_on_off",
            {
                "step_mode": StepMode,
                "step_size": t.uint8_t,
                "transition_time": t.uint16_t,
            },
            False,
        ),
        0x07: ZCLCommandDef("stop_with_on_off", {}, False),
        0x08: ZCLCommandDef(
            "move_to_closest_frequency", {"frequency": t.uint16_t}, False
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {}


class Alarms(Cluster):
    """Attributes and commands for sending notifications and
    configuring alarm functionality."""

    cluster_id = 0x0009
    ep_attribute = "alarms"
    attributes: dict[int, ZCLAttributeDef] = {
        # Alarm Information
        0x0000: ZCLAttributeDef("alarm_count", type=t.uint16_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "reset_alarm", {"alarm_code": t.uint8_t, "cluster_id": t.uint16_t}, False
        ),
        0x01: ZCLCommandDef("reset_all_alarms", {}, False),
        0x02: ZCLCommandDef("get_alarm", {}, False),
        0x03: ZCLCommandDef("reset_alarm_log", {}, False),
        # 0x04: ("publish_event_log", {}, False),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "alarm", {"alarm_code": t.uint8_t, "cluster_id": t.uint16_t}, False
        ),
        0x01: ZCLCommandDef(
            "get_alarm_response",
            {
                "status": foundation.Status,
                "alarm_code?": t.uint8_t,
                "cluster_id?": t.uint16_t,
                "timestamp?": t.uint32_t,
            },
            True,
        ),
        # 0x02: ("get_event_log", {}, False),
    }


class Time(Cluster):
    """Attributes and commands that provide a basic interface
    to a real-time clock."""

    class TimeStatus(t.bitmap8):
        Master = 0b00000001
        Synchronized = 0b00000010
        Master_for_Zone_and_DST = 0b00000100
        Superseding = 0b00001000

    cluster_id = 0x000A
    ep_attribute = "time"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef("time", type=t.UTCTime, access="r*w", mandatory=True),
        0x0001: ZCLAttributeDef(
            "time_status", type=t.bitmap8, access="r*w", mandatory=True
        ),
        0x0002: ZCLAttributeDef("time_zone", type=t.int32s, access="rw"),
        0x0003: ZCLAttributeDef("dst_start", type=t.uint32_t, access="rw"),
        0x0004: ZCLAttributeDef("dst_end", type=t.uint32_t, access="rw"),
        0x0005: ZCLAttributeDef("dst_shift", type=t.int32s, access="rw"),
        0x0006: ZCLAttributeDef("standard_time", type=t.StandardTime, access="r"),
        0x0007: ZCLAttributeDef("local_time", type=t.LocalTime, access="r"),
        0x0008: ZCLAttributeDef("last_set_time", type=t.UTCTime, access="r"),
        0x0009: ZCLAttributeDef("valid_until_time", type=t.UTCTime, access="rw"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}

    def handle_cluster_general_request(
        self,
        hdr: foundation.ZCLHeader,
        *args: list[Any],
        dst_addressing: AddressingMode | None = None,
    ):
        if hdr.command_id == foundation.GeneralCommand.Read_Attributes:
            data = {}
            for attr in args[0][0]:
                if attr == 0:
                    epoch = datetime(2000, 1, 1, 0, 0, 0, 0)
                    diff = datetime.utcnow() - epoch
                    data[attr] = diff.total_seconds()
                elif attr == 1:
                    data[attr] = 7
                elif attr == 2:
                    diff = datetime.fromtimestamp(86400) - datetime.utcfromtimestamp(
                        86400
                    )
                    data[attr] = diff.total_seconds()
                elif attr == 7:
                    epoch = datetime(2000, 1, 1, 0, 0, 0, 0)
                    diff = datetime.now() - epoch
                    data[attr] = diff.total_seconds()
                else:
                    data[attr] = None
            self.create_catching_task(self.read_attributes_rsp(data, tsn=hdr.tsn))


class RSSILocation(Cluster):
    """Attributes and commands that provide a means for
    exchanging location information and channel parameters
    among devices."""

    cluster_id = 0x000B
    ep_attribute = "rssi_location"

    class LocationMethod(t.enum8):
        Lateration = 0x00
        Signposting = 0x01
        RF_fingerprinting = 0x02
        Out_of_band = 0x03
        Centralized = 0x04

    attributes: dict[int, ZCLAttributeDef] = {
        # Location Information
        0x0000: ZCLAttributeDef("type", type=t.uint8_t, access="rw", mandatory=True),
        0x0001: ZCLAttributeDef(
            "method", type=LocationMethod, access="rw", mandatory=True
        ),
        0x0002: ZCLAttributeDef("age", type=t.uint16_t, access="r"),
        0x0003: ZCLAttributeDef("quality_measure", type=t.uint8_t, access="r"),
        0x0004: ZCLAttributeDef("num_of_devices", type=t.uint8_t, access="r"),
        # Location Settings
        0x0010: ZCLAttributeDef(
            "coordinate1", type=t.int16s, access="rw", mandatory=True
        ),
        0x0011: ZCLAttributeDef(
            "coordinate2", type=t.int16s, access="rw", mandatory=True
        ),
        0x0012: ZCLAttributeDef("coordinate3", type=t.int16s, access="rw"),
        0x0013: ZCLAttributeDef("power", type=t.int16s, access="rw", mandatory=True),
        0x0014: ZCLAttributeDef(
            "path_loss_exponent", type=t.uint16_t, access="rw", mandatory=True
        ),
        0x0015: ZCLAttributeDef("reporting_period", type=t.uint16_t, access="rw"),
        0x0016: ZCLAttributeDef("calculation_period", type=t.uint16_t, access="rw"),
        0x0017: ZCLAttributeDef(
            "number_rssi_measurements", type=t.uint8_t, access="rw", mandatory=True
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "set_absolute_location",
            {
                "coordinate1": t.int16s,
                "coordinate2": t.int16s,
                "coordinate3": t.int16s,
                "power": t.int16s,
                "path_loss_exponent": t.uint16_t,
            },
            False,
        ),
        0x01: ZCLCommandDef(
            "set_dev_config",
            {
                "power": t.int16s,
                "path_loss_exponent": t.uint16_t,
                "calculation_period": t.uint16_t,
                "num_rssi_measurements": t.uint8_t,
                "reporting_period": t.uint16_t,
            },
            False,
        ),
        0x02: ZCLCommandDef("get_dev_config", {"target_addr": t.EUI64}, False),
        0x03: ZCLCommandDef(
            "get_location_data",
            {"packed": t.bitmap8, "num_responses": t.uint8_t, "target_addr": t.EUI64},
            False,
        ),
        0x04: ZCLCommandDef(
            "rssi_response",
            {
                "replying_device": t.EUI64,
                "x": t.int16s,
                "y": t.int16s,
                "z": t.int16s,
                "rssi": t.int8s,
                "num_rssi_measurements": t.uint8_t,
            },
            True,
        ),
        0x05: ZCLCommandDef(
            "send_pings",
            {
                "target_addr": t.EUI64,
                "num_rssi_measurements": t.uint8_t,
                "calculation_period": t.uint16_t,
            },
            False,
        ),
        0x06: ZCLCommandDef(
            "anchor_node_announce",
            {
                "anchor_node_ieee_addr": t.EUI64,
                "x": t.int16s,
                "y": t.int16s,
                "z": t.int16s,
            },
            False,
        ),
    }

    class NeighborInfo(t.Struct):
        neighbor: t.EUI64
        x: t.int16s
        y: t.int16s
        z: t.int16s
        rssi: t.int8s
        num_measurements: t.uint8_t

    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "dev_config_response",
            {
                "status": foundation.Status,
                "power?": t.int16s,
                "path_loss_exponent?": t.uint16_t,
                "calculation_period?": t.uint16_t,
                "num_rssi_measurements?": t.uint8_t,
                "reporting_period?": t.uint16_t,
            },
            True,
        ),
        0x01: ZCLCommandDef(
            "location_data_response",
            {
                "status": foundation.Status,
                "location_type?": t.uint8_t,
                "coordinate1?": t.int16s,
                "coordinate2?": t.int16s,
                "coordinate3?": t.int16s,
                "power?": t.uint16_t,
                "path_loss_exponent?": t.uint8_t,
                "location_method?": t.uint8_t,
                "quality_measure?": t.uint8_t,
                "location_age?": t.uint16_t,
            },
            True,
        ),
        0x02: ZCLCommandDef("location_data_notification", {}, False),
        0x03: ZCLCommandDef("compact_location_data_notification", {}, False),
        0x04: ZCLCommandDef("rssi_ping", {"location_type": t.uint8_t}, False),  # data8
        0x05: ZCLCommandDef("rssi_req", {}, False),
        0x06: ZCLCommandDef(
            "report_rssi_measurements",
            {"measuring_device": t.EUI64, "neighbors": t.LVList[NeighborInfo]},
            False,
        ),
        0x07: ZCLCommandDef(
            "request_own_location", {"ieee_of_blind_node": t.EUI64}, False
        ),
    }


class AnalogInput(Cluster):
    cluster_id = 0x000C
    ep_attribute = "analog_input"

    class Reliability(t.enum8):
        No_fault_detected = 0
        No_sensor = 1
        Over_range = 2
        Under_range = 3
        Open_loop = 4
        Shorted_loop = 5
        No_output = 6
        Unreliable_other = 7
        Process_error = 8
        Multi_state_fault = 9
        Configuration_error = 10

    attributes: dict[int, ZCLAttributeDef] = {
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x0041: ZCLAttributeDef("max_present_value", type=t.Single, access="r*w"),
        0x0045: ZCLAttributeDef("min_present_value", type=t.Single, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Single, access="rwp", mandatory=True
        ),
        0x0067: ZCLAttributeDef("reliability", type=Reliability, access="r*w"),
        0x006A: ZCLAttributeDef("resolution", type=t.Single, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="rp", mandatory=True
        ),
        0x0075: ZCLAttributeDef("engineering_units", type=t.enum16, access="r*w"),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class AnalogOutput(Cluster):
    cluster_id = 0x000D
    ep_attribute = "analog_output"
    attributes: dict[int, ZCLAttributeDef] = {
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x0041: ZCLAttributeDef("max_present_value", type=t.Single, access="r*w"),
        0x0045: ZCLAttributeDef("min_present_value", type=t.Single, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Single, access="rwp", mandatory=True
        ),
        # 0x0057: ZCLAttributeDef('priority_array', type=TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x0068: ZCLAttributeDef("relinquish_default", type=t.Single, access="r*w"),
        0x006A: ZCLAttributeDef("resolution", type=t.Single, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="rp", mandatory=True
        ),
        0x0075: ZCLAttributeDef("engineering_units", type=t.enum16, access="r*w"),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class AnalogValue(Cluster):
    cluster_id = 0x000E
    ep_attribute = "analog_value"
    attributes: dict[int, ZCLAttributeDef] = {
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Single, access="rw", mandatory=True
        ),
        # 0x0057: ('priority_array', TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x0068: ZCLAttributeDef("relinquish_default", type=t.Single, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0075: ZCLAttributeDef("engineering_units", type=t.enum16, access="r*w"),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class BinaryInput(Cluster):
    cluster_id = 0x000F
    name = "Binary Input (Basic)"
    ep_attribute = "binary_input"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0004: ZCLAttributeDef("active_text", type=t.CharacterString, access="r*w"),
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x002E: ZCLAttributeDef("inactive_text", type=t.CharacterString, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0054: ZCLAttributeDef("polarity", type=t.enum8, access="r"),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class BinaryOutput(Cluster):
    cluster_id = 0x0010
    ep_attribute = "binary_output"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0004: ZCLAttributeDef("active_text", type=t.CharacterString, access="r*w"),
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x002E: ZCLAttributeDef("inactive_text", type=t.CharacterString, access="r*w"),
        0x0042: ZCLAttributeDef("minimum_off_time", type=t.uint32_t, access="r*w"),
        0x0043: ZCLAttributeDef("minimum_on_time", type=t.uint32_t, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0054: ZCLAttributeDef("polarity", type=t.enum8, access="r"),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Bool, access="r*w", mandatory=True
        ),
        # 0x0057: ('priority_array', TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x0068: ZCLAttributeDef("relinquish_default", type=t.Bool, access="r*w"),
        0x006A: ZCLAttributeDef(
            "resolution", type=t.Single, access="r"
        ),  # Does not seem to be in binary_output
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0075: ZCLAttributeDef(
            "engineering_units", type=t.enum16, access="r"
        ),  # Does not seem to be in binary_output
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class BinaryValue(Cluster):
    cluster_id = 0x0011
    ep_attribute = "binary_value"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0004: ZCLAttributeDef("active_text", type=t.CharacterString, access="r*w"),
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x002E: ZCLAttributeDef("inactive_text", type=t.CharacterString, access="r*w"),
        0x0042: ZCLAttributeDef("minimum_off_time", type=t.uint32_t, access="r*w"),
        0x0043: ZCLAttributeDef("minimum_on_time", type=t.uint32_t, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Single, access="r*w", mandatory=True
        ),
        # 0x0057: ZCLAttributeDef('priority_array', type=TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x0068: ZCLAttributeDef("relinquish_default", type=t.Single, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class MultistateInput(Cluster):
    cluster_id = 0x0012
    ep_attribute = "multistate_input"
    attributes: dict[int, ZCLAttributeDef] = {
        0x000E: ZCLAttributeDef(
            "state_text", type=t.List[t.CharacterString], access="r*w"
        ),
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x004A: ZCLAttributeDef("number_of_states", type=t.uint16_t, access="r*w"),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Single, access="r*w", mandatory=True
        ),
        # 0x0057: ('priority_array', TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class MultistateOutput(Cluster):
    cluster_id = 0x0013
    ep_attribute = "multistate_output"
    attributes: dict[int, ZCLAttributeDef] = {
        0x000E: ZCLAttributeDef(
            "state_text", type=t.List[t.CharacterString], access="r*w"
        ),
        0x001C: ZCLAttributeDef("description", type=t.CharacterString, access="r*w"),
        0x004A: ZCLAttributeDef(
            "number_of_states", type=t.uint16_t, access="r*w", mandatory=True
        ),
        0x0051: ZCLAttributeDef(
            "out_of_service", type=t.Bool, access="r*w", mandatory=True
        ),
        0x0055: ZCLAttributeDef(
            "present_value", type=t.Single, access="r*w", mandatory=True
        ),
        # 0x0057: ZCLAttributeDef('priority_array', type=TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", type=t.enum8, access="r*w"),
        0x0068: ZCLAttributeDef("relinquish_default", type=t.Single, access="r*w"),
        0x006F: ZCLAttributeDef(
            "status_flags", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0100: ZCLAttributeDef("application_type", type=t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class MultistateValue(Cluster):
    cluster_id = 0x0014
    ep_attribute = "multistate_value"
    attributes: dict[int, ZCLAttributeDef] = {
        0x000E: ZCLAttributeDef("state_text", t.List[t.CharacterString], access="r*w"),
        0x001C: ZCLAttributeDef("description", t.CharacterString, access="r*w"),
        0x004A: ZCLAttributeDef(
            "number_of_states", t.uint16_t, access="r*w", mandatory=True
        ),
        0x0051: ZCLAttributeDef("out_of_service", t.Bool, access="r*w", mandatory=True),
        0x0055: ZCLAttributeDef(
            "present_value", t.Single, access="r*w", mandatory=True
        ),
        # 0x0057: ('priority_array', TODO.array),  # Array of 16 structures of (boolean,
        # single precision)
        0x0067: ZCLAttributeDef("reliability", t.enum8, access="r*w"),
        0x0068: ZCLAttributeDef("relinquish_default", t.Single, access="r*w"),
        0x006F: ZCLAttributeDef("status_flags", t.bitmap8, access="r", mandatory=True),
        0x0100: ZCLAttributeDef("application_type", t.uint32_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class Commissioning(Cluster):
    """Attributes and commands for commissioning and
    managing a ZigBee device."""

    cluster_id = 0x0015
    ep_attribute = "commissioning"

    class StartupControl(t.enum8):
        Part_of_network = 0x00
        Form_network = 0x01
        Rejoin_network = 0x02
        Start_from_scratch = 0x03

    class NetworkKeyType(t.enum8):
        Standard = 0x01

    attributes: dict[int, ZCLAttributeDef] = {
        # Startup Parameters
        0x0000: ZCLAttributeDef(
            "short_address", type=t.uint16_t, access="rw", mandatory=True
        ),
        0x0001: ZCLAttributeDef(
            "extended_pan_id", type=t.EUI64, access="rw", mandatory=True
        ),
        0x0002: ZCLAttributeDef("pan_id", type=t.uint16_t, access="rw", mandatory=True),
        0x0003: ZCLAttributeDef(
            "channel_mask", type=t.Channels, access="rw", mandatory=True
        ),
        0x0004: ZCLAttributeDef(
            "protocol_version", type=t.uint8_t, access="rw", mandatory=True
        ),
        0x0005: ZCLAttributeDef(
            "stack_profile", type=t.uint8_t, access="rw", mandatory=True
        ),
        0x0006: ZCLAttributeDef(
            "startup_control", type=StartupControl, access="rw", mandatory=True
        ),
        0x0010: ZCLAttributeDef(
            "trust_center_address", type=t.EUI64, access="rw", mandatory=True
        ),
        0x0011: ZCLAttributeDef("trust_center_master_key", type=t.KeyData, access="rw"),
        0x0012: ZCLAttributeDef(
            "network_key", type=t.KeyData, access="rw", mandatory=True
        ),
        0x0013: ZCLAttributeDef(
            "use_insecure_join", type=t.Bool, access="rw", mandatory=True
        ),
        0x0014: ZCLAttributeDef(
            "preconfigured_link_key", type=t.KeyData, access="rw", mandatory=True
        ),
        0x0015: ZCLAttributeDef(
            "network_key_seq_num", type=t.uint8_t, access="rw", mandatory=True
        ),
        0x0016: ZCLAttributeDef(
            "network_key_type", type=NetworkKeyType, access="rw", mandatory=True
        ),
        0x0017: ZCLAttributeDef(
            "network_manager_address", type=t.uint16_t, access="rw", mandatory=True
        ),
        # Join Parameters
        0x0020: ZCLAttributeDef("scan_attempts", type=t.uint8_t, access="rw"),
        0x0021: ZCLAttributeDef("time_between_scans", type=t.uint16_t, access="rw"),
        0x0022: ZCLAttributeDef("rejoin_interval", type=t.uint16_t, access="rw"),
        0x0023: ZCLAttributeDef("max_rejoin_interval", type=t.uint16_t, access="rw"),
        # End Device Parameters
        0x0030: ZCLAttributeDef("indirect_poll_rate", type=t.uint16_t, access="rw"),
        0x0031: ZCLAttributeDef("parent_retry_threshold", type=t.uint8_t, access="r"),
        # Concentrator Parameters
        0x0040: ZCLAttributeDef("concentrator_flag", type=t.Bool, access="rw"),
        0x0041: ZCLAttributeDef("concentrator_radius", type=t.uint8_t, access="rw"),
        0x0042: ZCLAttributeDef(
            "concentrator_discovery_time", type=t.uint8_t, access="rw"
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "restart_device",
            {"options": t.bitmap8, "delay": t.uint8_t, "jitter": t.uint8_t},
            False,
        ),
        0x01: ZCLCommandDef(
            "save_startup_parameters", {"options": t.bitmap8, "index": t.uint8_t}, False
        ),
        0x02: ZCLCommandDef(
            "restore_startup_parameters",
            {"options": t.bitmap8, "index": t.uint8_t},
            False,
        ),
        0x03: ZCLCommandDef(
            "reset_startup_parameters",
            {"options": t.bitmap8, "index": t.uint8_t},
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "restart_device_response", {"status": foundation.Status}, True
        ),
        0x01: ZCLCommandDef(
            "save_startup_params_response", {"status": foundation.Status}, True
        ),
        0x02: ZCLCommandDef(
            "restore_startup_params_response", {"status": foundation.Status}, True
        ),
        0x03: ZCLCommandDef(
            "reset_startup_params_response", {"status": foundation.Status}, True
        ),
    }


class Partition(Cluster):
    cluster_id = 0x0016
    ep_attribute = "partition"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "maximum_incoming_transfer_size",
            type=t.uint16_t,
            access="r",
            mandatory=True,
        ),
        0x0001: ZCLAttributeDef(
            "maximum_outgoing_transfer_size",
            type=t.uint16_t,
            access="r",
            mandatory=True,
        ),
        0x0002: ZCLAttributeDef(
            "partitioned_frame_size", type=t.uint8_t, access="rw", mandatory=True
        ),
        0x0003: ZCLAttributeDef(
            "large_frame_size", type=t.uint16_t, access="rw", mandatory=True
        ),
        0x0004: ZCLAttributeDef(
            "number_of_ack_frame", type=t.uint8_t, access="rw", mandatory=True
        ),
        0x0005: ZCLAttributeDef(
            "nack_timeout", type=t.uint16_t, access="r", mandatory=True
        ),
        0x0006: ZCLAttributeDef(
            "interframe_delay", type=t.uint8_t, access="rw", mandatory=True
        ),
        0x0007: ZCLAttributeDef(
            "number_of_send_retries", type=t.uint8_t, access="r", mandatory=True
        ),
        0x0008: ZCLAttributeDef(
            "sender_timeout", type=t.uint16_t, access="r", mandatory=True
        ),
        0x0009: ZCLAttributeDef(
            "receiver_timeout", type=t.uint16_t, access="r", mandatory=True
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class Ota(Cluster):
    class ImageUpgradeStatus(t.enum8):
        Normal = 0x00
        Download_in_progress = 0x01
        Download_complete = 0x02
        Waiting_to_upgrade = 0x03
        Count_down = 0x04
        Wait_for_more = 0x05
        Waiting_to_Upgrade_via_External_Event = 0x06

    class UpgradeActivationPolicy(t.enum8):
        OTA_server_allowed = 0x00
        Out_of_band_allowed = 0x01

    class UpgradeTimeoutPolicy(t.enum8):
        Apply_after_timeout = 0x00
        Do_not_apply_after_timeout = 0x01

    class ImageNotifyCommand(foundation.CommandSchema):
        class PayloadType(t.enum8):
            QueryJitter = 0x00
            QueryJitter_ManufacturerCode = 0x01
            QueryJitter_ManufacturerCode_ImageType = 0x02
            QueryJitter_ManufacturerCode_ImageType_NewFileVersion = 0x03

        payload_type: None = t.StructField(type=PayloadType)
        query_jitter: t.uint8_t
        manufacturer_code: t.uint16_t = t.StructField(
            requires=(
                lambda s: s.payload_type >= s.PayloadType.QueryJitter_ManufacturerCode
            )
        )
        image_type: t.uint16_t = t.StructField(
            requires=(
                lambda s: s.payload_type
                >= s.PayloadType.QueryJitter_ManufacturerCode_ImageType
            )
        )
        new_file_version: t.uint32_t = t.StructField(
            requires=(
                lambda s: s.payload_type
                >= s.PayloadType.QueryJitter_ManufacturerCode_ImageType_NewFileVersion
            )
        )

    class QueryNextImageCommand(foundation.CommandSchema):
        class FieldControl(t.bitmap8):
            HardwareVersion = 0b00000001

        field_control: None = t.StructField(type=FieldControl)
        manufacturer_code: t.uint16_t
        image_type: t.uint16_t
        current_file_version: t.uint32_t
        hardware_version: t.uint16_t = t.StructField(
            requires=(lambda s: s.field_control & s.FieldControl.HardwareVersion)
        )

    class ImageBlockCommand(foundation.CommandSchema):
        class FieldControl(t.bitmap8):
            RequestNodeAddr = 0b00000001
            MinimumBlockPeriod = 0b00000010

        field_control: None = t.StructField(type=FieldControl)
        manufacturer_code: t.uint16_t
        image_type: t.uint16_t
        file_version: t.uint32_t
        file_offset: t.uint32_t
        maximum_data_size: t.uint8_t
        request_node_addr: t.EUI64 = t.StructField(
            requires=(lambda s: s.field_control & s.FieldControl.RequestNodeAddr)
        )
        minimum_block_period: t.uint16_t = t.StructField(
            requires=(lambda s: s.field_control & s.FieldControl.MinimumBlockPeriod)
        )

    class ImagePageCommand(foundation.CommandSchema):
        class FieldControl(t.bitmap8):
            RequestNodeAddr = 0b00000001

        field_control: None = t.StructField(type=FieldControl)
        manufacturer_code: t.uint16_t
        image_type: t.uint16_t
        file_version: t.uint32_t
        file_offset: t.uint32_t
        maximum_data_size: t.uint8_t
        page_size: t.uint16_t
        response_spacing: t.uint16_t
        request_node_addr: t.EUI64 = t.StructField(
            requires=lambda s: s.field_control & s.FieldControl.RequestNodeAddr
        )

    class ImageBlockResponseCommand(foundation.CommandSchema):
        # All responses contain at least a status
        status: foundation.Status

        # Payload with `SUCCESS` status
        manufacturer_code: t.uint16_t = t.StructField(
            requires=lambda s: s.status == foundation.Status.SUCCESS
        )
        image_type: t.uint16_t = t.StructField(
            requires=lambda s: s.status == foundation.Status.SUCCESS
        )
        file_version: t.uint32_t = t.StructField(
            requires=lambda s: s.status == foundation.Status.SUCCESS
        )
        file_offset: t.uint32_t = t.StructField(
            requires=lambda s: s.status == foundation.Status.SUCCESS
        )
        image_data: t.LVBytes = t.StructField(
            requires=lambda s: s.status == foundation.Status.SUCCESS
        )

        # Payload with `WAIT_FOR_DATA` status
        current_time: t.UTCTime = t.StructField(
            requires=lambda s: s.status == foundation.Status.WAIT_FOR_DATA
        )
        request_time: t.UTCTime = t.StructField(
            requires=lambda s: s.status == foundation.Status.WAIT_FOR_DATA
        )
        minimum_block_period: t.uint16_t = t.StructField(
            requires=lambda s: s.status == foundation.Status.WAIT_FOR_DATA
        )

    cluster_id = 0x0019
    ep_attribute = "ota"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "upgrade_server_id", type=t.EUI64, access="r", mandatory=True
        ),
        0x0001: ZCLAttributeDef("file_offset", type=t.uint32_t, access="r"),
        0x0002: ZCLAttributeDef("current_file_version", type=t.uint32_t, access="r"),
        0x0003: ZCLAttributeDef(
            "current_zigbee_stack_version", type=t.uint16_t, access="r"
        ),
        0x0004: ZCLAttributeDef("downloaded_file_version", type=t.uint32_t, access="r"),
        0x0005: ZCLAttributeDef(
            "downloaded_zigbee_stack_version", type=t.uint16_t, access="r"
        ),
        0x0006: ZCLAttributeDef(
            "image_upgrade_status", type=ImageUpgradeStatus, access="r", mandatory=True
        ),
        0x0007: ZCLAttributeDef("manufacturer_id", type=t.uint16_t, access="r"),
        0x0008: ZCLAttributeDef("image_type_id", type=t.uint16_t, access="r"),
        0x0009: ZCLAttributeDef("minimum_block_req_delay", type=t.uint16_t, access="r"),
        0x000A: ZCLAttributeDef("image_stamp", type=t.uint32_t, access="r"),
        0x000B: ZCLAttributeDef(
            "upgrade_activation_policy", type=UpgradeActivationPolicy, access="r"
        ),
        0x000C: ZCLAttributeDef(
            "upgrade_timeout_policy", type=UpgradeTimeoutPolicy, access="r"
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x01: ZCLCommandDef("query_next_image", QueryNextImageCommand, False),
        0x03: ZCLCommandDef("image_block", ImageBlockCommand, False),
        0x04: ZCLCommandDef("image_page", ImagePageCommand, False),
        0x06: ZCLCommandDef(
            "upgrade_end",
            {
                "status": foundation.Status,
                "manufacturer_code": t.uint16_t,
                "image_type": t.uint16_t,
                "file_version": t.uint32_t,
            },
            False,
        ),
        0x08: ZCLCommandDef(
            "query_specific_file",
            {
                "request_node_addr": t.EUI64,
                "manufacturer_code": t.uint16_t,
                "image_type": t.uint16_t,
                "file_version": t.uint32_t,
                "current_zigbee_stack_version": t.uint16_t,
            },
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef("image_notify", ImageNotifyCommand, False),
        0x02: ZCLCommandDef(
            "query_next_image_response",
            {
                "status": foundation.Status,
                "manufacturer_code?": t.uint16_t,
                "image_type?": t.uint16_t,
                "file_version?": t.uint32_t,
                "image_size?": t.uint32_t,
            },
            True,
        ),
        0x05: ZCLCommandDef(
            "image_block_response",
            ImageBlockResponseCommand,
            True,
        ),
        0x07: ZCLCommandDef(
            "upgrade_end_response",
            {
                "manufacturer_code": t.uint16_t,
                "image_type": t.uint16_t,
                "file_version": t.uint32_t,
                "current_time": t.UTCTime,
                "upgrade_time": t.UTCTime,
            },
            True,
        ),
        0x09: ZCLCommandDef(
            "query_specific_file_response",
            {
                "status": foundation.Status,
                "manufacturer_code?": t.uint16_t,
                "image_type?": t.uint16_t,
                "file_version?": t.uint32_t,
                "image_size?": t.uint32_t,
            },
            True,
        ),
    }

    def handle_cluster_request(
        self,
        hdr: foundation.ZCLHeader,
        args: list[Any],
        *,
        dst_addressing: AddressingMode | None = None,
    ):
        self.create_catching_task(
            self._handle_cluster_request(hdr, args, dst_addressing=dst_addressing),
        )

    async def _handle_cluster_request(
        self,
        hdr: foundation.ZCLHeader,
        args: list[Any],
        *,
        dst_addressing: AddressingMode | None = None,
    ):
        """Parse OTA commands."""
        tsn, command_id = hdr.tsn, hdr.command_id

        try:
            cmd_name = self.server_commands[command_id].name
        except KeyError:
            self.warning("Unknown OTA command id %d (%s)", command_id, args)
            return

        if cmd_name == "query_next_image":
            await self._handle_query_next_image(
                *args, tsn=tsn, model=self.endpoint.model
            )
        elif cmd_name == "image_block":
            await self._handle_image_block(*args, tsn=tsn, model=self.endpoint.model)
        elif cmd_name == "upgrade_end":
            await self._handle_upgrade_end(*args, tsn=tsn)
        else:
            self.debug(
                "no '%s' OTA command handler for '%s %s': %s",
                cmd_name,
                self.endpoint.manufacturer,
                self.endpoint.model,
                args,
            )

    async def _handle_query_next_image(
        self,
        field_ctrl,
        manufacturer_id,
        image_type,
        current_file_version,
        hardware_version,
        *,
        tsn,
        model=None,
    ):
        self.debug(
            (
                "OTA query_next_image handler for '%s %s': "
                "field_control=%s, manufacturer_id=%s, image_type=%s, "
                "current_file_version=%s, hardware_version=%s, model=%r"
            ),
            self.endpoint.manufacturer,
            self.endpoint.model,
            field_ctrl,
            manufacturer_id,
            image_type,
            current_file_version,
            hardware_version,
            model,
        )

        img = await self.endpoint.device.application.ota.get_ota_image(
            manufacturer_id, image_type, model
        )

        if img is not None:
            should_update = img.should_update(
                manufacturer_id, image_type, current_file_version, hardware_version
            )
            self.debug(
                "OTA image version: %s, size: %s. Update needed: %s",
                img.version,
                img.header.image_size,
                should_update,
            )
            if should_update:
                self.info(
                    "Updating: %s %s", self.endpoint.manufacturer, self.endpoint.model
                )
                await self.query_next_image_response(
                    foundation.Status.SUCCESS,
                    img.key.manufacturer_id,
                    img.key.image_type,
                    img.version,
                    img.header.image_size,
                    tsn=tsn,
                )
                return
        else:
            self.debug("No OTA image is available")
        await self.query_next_image_response(
            foundation.Status.NO_IMAGE_AVAILABLE, tsn=tsn
        )

    async def _handle_image_block(
        self,
        field_ctr,
        manufacturer_id,
        image_type,
        file_version,
        file_offset,
        max_data_size,
        request_node_addr,
        block_request_delay,
        *,
        tsn=None,
        model=None,
    ):
        self.debug(
            (
                "OTA image_block handler for '%s %s': field_control=%s"
                ", manufacturer_id=%s, image_type=%s, file_version=%s"
                ", file_offset=%s, max_data_size=%s, request_node_addr=%s"
                ", block_request_delay=%s"
            ),
            self.endpoint.manufacturer,
            self.endpoint.model,
            field_ctr,
            manufacturer_id,
            image_type,
            file_version,
            file_offset,
            max_data_size,
            request_node_addr,
            block_request_delay,
        )
        img = await self.endpoint.device.application.ota.get_ota_image(
            manufacturer_id, image_type, model
        )
        if img is None or img.version != file_version:
            self.debug("OTA image is not available")
            await self.image_block_response(foundation.Status.ABORT, tsn=tsn)
            return
        self.debug(
            "OTA upgrade progress: %0.1f", 100.0 * file_offset / img.header.image_size
        )
        try:
            block = img.get_image_block(file_offset, max_data_size)
        except ValueError:
            await self.image_block_response(
                foundation.Status.MALFORMED_COMMAND, tsn=tsn
            )
        else:
            await self.image_block_response(
                foundation.Status.SUCCESS,
                img.key.manufacturer_id,
                img.key.image_type,
                img.version,
                file_offset,
                block,
                tsn=tsn,
            )

    async def _handle_upgrade_end(
        self, status, manufacturer_id, image_type, file_ver, *, tsn
    ):
        self.debug(
            (
                "OTA upgrade_end handler for '%s %s': status=%s"
                ", manufacturer_id=%s, image_type=%s, file_version=%s"
            ),
            self.endpoint.manufacturer,
            self.endpoint.model,
            status,
            manufacturer_id,
            image_type,
            file_ver,
        )
        await self.upgrade_end_response(
            manufacturer_id, image_type, file_ver, 0x00000000, 0x00000000, tsn=tsn
        )


class PowerProfile(Cluster):
    cluster_id = 0x001A
    ep_attribute = "power_profile"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "total_profile_num", type=t.uint8_t, access="r", mandatory=True
        ),
        0x0001: ZCLAttributeDef(
            "multiple_scheduling", type=t.Bool, access="r", mandatory=True
        ),
        0x0002: ZCLAttributeDef(
            "energy_formatting", type=t.bitmap8, access="r", mandatory=True
        ),
        0x0003: ZCLAttributeDef(
            "energy_remote", type=t.Bool, access="r", mandatory=True
        ),
        0x0004: ZCLAttributeDef(
            "schedule_mode", type=t.bitmap8, access="rwp", mandatory=True
        ),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }

    class ScheduleRecord(t.Struct):
        phase_id: t.uint8_t
        scheduled_time: t.uint16_t

    class PowerProfilePhase(t.Struct):
        energy_phase_id: t.uint8_t
        macro_phase_id: t.uint8_t
        expected_duration: t.uint16_t
        peak_power: t.uint16_t
        energy: t.uint16_t

    class PowerProfile(t.Struct):
        power_profile_id: t.uint8_t
        energy_phase_id: t.uint8_t
        power_profile_remote_control: t.Bool
        power_profile_state: t.uint8_t

    # XXX: are these flipped?
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "power_profile_request", {"power_profile_id": t.uint8_t}, False
        ),
        0x01: ZCLCommandDef("power_profile_state_request", {}, False),
        0x02: ZCLCommandDef(
            "get_power_profile_price_response",
            {
                "power_profile_id": t.uint8_t,
                "currency": t.uint16_t,
                "price": t.uint32_t,
                "price_trailing_digit": t.uint8_t,
            },
            True,
        ),
        0x03: ZCLCommandDef(
            "get_overall_schedule_price_response",
            {
                "currency": t.uint16_t,
                "price": t.uint32_t,
                "price_trailing_digit": t.uint8_t,
            },
            True,
        ),
        0x04: ZCLCommandDef(
            "energy_phases_schedule_notification",
            {
                "power_profile_id": t.uint8_t,
                "scheduled_phases": t.LVList[ScheduleRecord],
            },
            False,
        ),
        0x05: ZCLCommandDef(
            "energy_phases_schedule_response",
            {
                "power_profile_id": t.uint8_t,
                "scheduled_phases": t.LVList[ScheduleRecord],
            },
            True,
        ),
        0x06: ZCLCommandDef(
            "power_profile_schedule_constraints_request",
            {"power_profile_id": t.uint8_t},
            False,
        ),
        0x07: ZCLCommandDef(
            "energy_phases_schedule_state_request",
            {"power_profile_id": t.uint8_t},
            False,
        ),
        0x08: ZCLCommandDef(
            "get_power_profile_price_extended_response",
            {
                "power_profile_id": t.uint8_t,
                "currency": t.uint16_t,
                "price": t.uint32_t,
                "price_trailing_digit": t.uint8_t,
            },
            True,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "power_profile_notification",
            {
                "total_profile_num": t.uint8_t,
                "power_profile_id": t.uint8_t,
                "transfer_phases": t.LVList[PowerProfilePhase],
            },
            False,
        ),
        0x01: ZCLCommandDef(
            "power_profile_response",
            {
                "total_profile_num": t.uint8_t,
                "power_profile_id": t.uint8_t,
                "transfer_phases": t.LVList[PowerProfilePhase],
            },
            True,
        ),
        0x02: ZCLCommandDef(
            "power_profile_state_response",
            {"power_profiles": t.LVList[PowerProfile]},
            True,
        ),
        0x03: ZCLCommandDef(
            "get_power_profile_price", {"power_profile_id": t.uint8_t}, False
        ),
        0x04: ZCLCommandDef(
            "power_profile_state_notification",
            {"power_profiles": t.LVList[PowerProfile]},
            False,
        ),
        0x05: ZCLCommandDef("get_overall_schedule_price", {}, False),
        0x06: ZCLCommandDef(
            "energy_phases_schedule_request",
            {"power_profile_id": t.uint8_t},
            False,
        ),
        0x07: ZCLCommandDef(
            "energy_phases_schedule_state_response",
            {"power_profile_id": t.uint8_t, "num_scheduled_energy_phases": t.uint8_t},
            True,
        ),
        0x08: ZCLCommandDef(
            "energy_phases_schedule_state_notification",
            {"power_profile_id": t.uint8_t, "num_scheduled_energy_phases": t.uint8_t},
            False,
        ),
        0x09: ZCLCommandDef(
            "power_profile_schedule_constraints_notification",
            {
                "power_profile_id": t.uint8_t,
                "start_after": t.uint16_t,
                "stop_before": t.uint16_t,
            },
            False,
        ),
        0x0A: ZCLCommandDef(
            "power_profile_schedule_constraints_response",
            {
                "power_profile_id": t.uint8_t,
                "start_after": t.uint16_t,
                "stop_before": t.uint16_t,
            },
            True,
        ),
        0x0B: ZCLCommandDef(
            "get_power_profile_price_extended",
            {
                "options": t.bitmap8,
                "power_profile_id": t.uint8_t,
                "power_profile_start_time?": t.uint16_t,
            },
            False,
        ),
    }


class ApplianceControl(Cluster):
    cluster_id = 0x001B
    ep_attribute = "appliance_control"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "start_time", type=t.uint16_t, access="rp", mandatory=True
        ),
        0x0001: ZCLAttributeDef(
            "finish_time", type=t.uint16_t, access="rp", mandatory=True
        ),
        0x0002: ZCLAttributeDef("remaining_time", type=t.uint16_t, access="rp"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {}
    client_commands: dict[int, ZCLCommandDef] = {}


class PollControl(Cluster):
    cluster_id = 0x0020
    name = "Poll Control"
    ep_attribute = "poll_control"
    attributes: dict[int, ZCLAttributeDef] = {
        0x0000: ZCLAttributeDef(
            "checkin_interval", type=t.uint32_t, access="rw", mandatory=True
        ),
        0x0001: ZCLAttributeDef(
            "long_poll_interval", type=t.uint32_t, access="r", mandatory=True
        ),
        0x0002: ZCLAttributeDef(
            "short_poll_interval", type=t.uint16_t, access="r", mandatory=True
        ),
        0x0003: ZCLAttributeDef(
            "fast_poll_timeout", type=t.uint16_t, access="rw", mandatory=True
        ),
        0x0004: ZCLAttributeDef("checkin_interval_min", type=t.uint32_t, access="r"),
        0x0005: ZCLAttributeDef("long_poll_interval_min", type=t.uint32_t, access="r"),
        0x0006: ZCLAttributeDef("fast_poll_timeout_max", type=t.uint16_t, access="r"),
        0xFFFD: foundation.ZCL_CLUSTER_REVISION_ATTR,
        0xFFFE: foundation.ZCL_REPORTING_STATUS_ATTR,
    }
    server_commands: dict[int, ZCLCommandDef] = {
        0x00: ZCLCommandDef(
            "checkin_response",
            {"start_fast_polling": t.Bool, "fast_poll_timeout": t.uint16_t},
            True,
        ),
        0x01: ZCLCommandDef("fast_poll_stop", {}, False),
        0x02: ZCLCommandDef(
            "set_long_poll_interval", {"new_long_poll_interval": t.uint32_t}, False
        ),
        0x03: ZCLCommandDef(
            "set_short_poll_interval",
            {"new_short_poll_interval": t.uint16_t},
            False,
        ),
    }
    client_commands: dict[int, ZCLCommandDef] = {
        0x0000: ZCLCommandDef("checkin", {}, False)
    }


class GreenPowerProxy(Cluster):
    cluster_id = 0x0021
    ep_attribute = "green_power"
    group = 0x0B84
    endpoint_id = 242
    attributes = {
        0x0000: ("max_sink_table_entries", t.uint8_t),
        0x0001: ("sink_table", t.LongOctetString),
        0x0002: ("communication_mode", t.bitmap8),
        0x0003: ("commissioning_exit_mode", t.bitmap8),
        0x0004: ("commissioning_window", t.uint16_t),
        0x0005: ("security_level", t.bitmap8),
        0x0006: ("functionality", t.bitmap24),
        0x0007: ("active_functionality", t.bitmap24),
        0x9997: ("joiningAllowUntil", t.uint32_t),
        0x9998: ("key", t.uint32_t),
        0x9999: ("counter", t.uint64_t),
    }
    server_commands = {
        0x0000: ("notification", (t.Struct,), False),
        0x0001: ("pairing_search ", (t.Struct,), False),
        0x0003: ("tunneling_stop", (t.Struct,), False),
        0x0004: ("commissioning_notification", (t.Struct,), False),
        0x0007: ("translation_table_update_command", (t.Struct,), False),
        0x0008: ("translation_table_request", (t.bitmap8,), False),
        0x0009: ("pairing_configuration", (t.Struct,), False),
    }
    command = {
        0x00: ("Identify", "CLUSTER_COMMAND", (), None, None, ()),
        0x10: ("Scene 0", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 0)),
        0x11: (
            "Scene 1",
            "CLUSTER_COMMAND",
            (),
            0x0005,
            0x0001,
            (
                0,
                1,
            ),
        ),
        0x12: ("Scene 2", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 2)),
        0x13: ("Scene 3", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 3)),
        0x14: ("Scene 4", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 4)),
        0x15: ("Scene 5", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 5)),
        0x17: ("Scene 7", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 6)),
        0x16: ("Scene 6", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 7)),
        0x18: ("Scene 8", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 8)),
        0x19: ("Scene 9", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 9)),
        0x1A: ("Scene 10", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 10)),
        0x1B: ("Scene 11", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 11)),
        0x1C: ("Scene 12", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 12)),
        0x1D: ("Scene 13", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 13)),
        0x1E: ("Scene 14", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 14)),
        0x1F: ("Scene 15", "CLUSTER_COMMAND", (), 0x0005, 0x0001, (0, 15)),
        0x20: ("Off", "CLUSTER_COMMAND", (), 0x0006, 0x0000, ()),
        0x21: ("On", "CLUSTER_COMMAND", (), 0x0006, 0x0001, ()),
        0x22: ("Toggle", "CLUSTER_COMMAND", (), 0x0006, 0x0002, ()),
        0x23: ("Release", "CLUSTER_COMMAND", (), None, None, ()),
        0x30: ("Move Up", "CLUSTER_COMMAND", (t.uint8_t,), 0x0008, 0x0001, (1,)),
        0x31: ("Move Down", "CLUSTER_COMMAND", (t.uint8_t,), 0x0008, 0x0000, (0,)),
        0x32: (
            "Step Up",
            "CLUSTER_COMMAND",
            (t.uint8_t, t.Optional(t.uint16_t)),
            0x0008,
            0x0002,
            (1,),
        ),
        0x33: (
            "Step Down",
            "CLUSTER_COMMAND",
            (t.uint8_t, t.Optional(t.uint16_t)),
            0x0008,
            0x0002,
            (0,),
        ),
        0x34: ("Level Control/Stop", "CLUSTER_COMMAND", (), 0x0008, 0x0007, ()),
        0x35: (
            "Move Up (with On/Off)",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0008,
            0x0005,
            (1,),
        ),
        0x36: (
            "Move Down (with On/Off)",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0008,
            0x0005,
            (0,),
        ),
        0x37: (
            "Step Up (with On/Off)",
            "CLUSTER_COMMAND",
            (t.uint8_t, t.Optional(t.uint16_t)),
            0x0008,
            0x0006,
            (1,),
        ),
        0x38: (
            "Step Down (with On/Off)",
            "CLUSTER_COMMAND",
            (t.uint8_t, t.Optional(t.uint16_t)),
            0x0008,
            0x0006,
            (0,),
        ),
        0x40: ("Move Hue Stop", "CLUSTER_COMMAND", (), 0x0300, 0x0047, ()),
        0x41: (
            "Move Hue Up Color",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0300,
            0x0001,
            (1,),
        ),
        0x42: (
            "Move Hue Down Color",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0300,
            0x0001,
            (0,),
        ),
        0x43: (
            "Step Hue Up Color",
            "CLUSTER_COMMAND",
            (t.uint8_t, t.Optional(t.uint16_t)),
            0x0300,
            0x0002,
            (1,),
        ),
        0x44: (
            "Step Hue Down Color",
            "CLUSTER_COMMAND",
            (t.uint8_t, t.Optional(t.uint16_t)),
            0x0300,
            0x0002,
            (0,),
        ),
        0x46: (
            "Move Saturation Up",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0300,
            0x0004,
            (1,),
        ),
        0x47: (
            "Move Saturation Down",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0300,
            0x0004,
            (0,),
        ),
        0x48: (
            "Step Saturation Up",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0300,
            0x0005,
            (1,),
        ),
        0x49: (
            "Step Saturation Down",
            "CLUSTER_COMMAND",
            (t.uint8_t,),
            0x0300,
            0x0005,
            (0,),
        ),
        0x4A: (
            "Move Color",
            "CLUSTER_COMMAND",
            (t.uint16_t, t.uint16_t),
            0x0300,
            0x0008,
            (),
        ),
        0x4B: (
            "Step Color",
            "CLUSTER_COMMAND",
            (t.uint16_t, t.uint16_t, t.Optional(t.uint16_t)),
            0x0300,
            0x0009,
            (),
        ),
        0x45: ("Move Saturation Stop", "CLUSTER_COMMAND", (), 0x0300, 0x0047, ()),
        0x50: ("Lock Door", "CLUSTER_COMMAND", (), 0x0101, 0x0000, ()),
        0x51: ("Unlock Door", "CLUSTER_COMMAND", (), 0x0101, 0x0001, ()),
        0x60: ("Press 1 of 1", "CLUSTER_COMMAND", (), None, None, ()),
        0x61: ("Release 1 of 1", "CLUSTER_COMMAND", (), None, None, ()),
        0x62: ("Press 1 of 2", "CLUSTER_COMMAND", (), None, None, ()),
        0x63: ("Release 1 of 2", "CLUSTER_COMMAND", (), None, None, ()),
        0x64: ("Press 2 of 2", "CLUSTER_COMMAND", (), None, None, ()),
        0x65: ("Release 2 of 2", "CLUSTER_COMMAND", (), None, None, ()),
        0x66: ("Short press 1 of 1", "CLUSTER_COMMAND", (), None, None, ()),
        0x67: ("Short press 1 of 2", "CLUSTER_COMMAND", (), None, None, ()),
        0x68: ("Short press 2 of 2", "CLUSTER_COMMAND", (), None, None, ()),
        0x69: ("Press", "CLUSTER_COMMAND", (t.uint8_t,), 0x0005, 0x0001, (0,)),
        0x6A: ("Release", "CLUSTER_COMMAND", (t.uint8_t,), None, None, ()),
    }
    device = {
        0x00: ("Simple Generic 1-state Switch", [], [0x0006]),
        0x01: ("Simple Generic 2-state Switch", [], [0x0006]),
        0x02: ("On/Off Switch", [], [0x0005, 0x0006]),
        0x03: ("Level Control Switch", [], [0x0008]),
        0x04: ("Simple Sensor", [], []),
        0x05: ("Advanced Generic 1-state Switch", [], [0x0005, 0x0006]),
        0x06: ("Advanced Generic 2-state Switch", [], [0x0005, 0x0006]),
        0x07: ("Generic Switch", [], [0x0005, 0x0006]),
        0x10: ("Color Dimmer Switch", [], [0x0300]),
        0x11: ("Light Sensor", [0x0400], []),
        0x12: ("Occupancy Sensor", [0x0406], []),
        0x20: ("Door Lock Controller", [], [0x0101]),
        0x30: ("Temperature Sensor", [0x0402], []),
        0x31: ("Pressure Sensor", [0x0403], []),
        0x32: ("Flow Sensor", [0x0404], []),
        0x33: ("Indoor Environment Sensor", [], []),
    }
    device = {
        0x00: ("Simple Generic 1-state Switch", [], [0x0006]),
        0x01: ("Simple Generic 2-state Switch", [], [0x0006]),
        0x02: ("On/Off Switch", [], [0x0005, 0x0006]),
        0x03: ("Level Control Switch", [], [0x0008]),
        0x04: ("Simple Sensor", [], []),
        0x05: ("Advanced Generic 1-state Switch", [], [0x0005, 0x0006]),
        0x06: ("Advanced Generic 2-state Switch", [], [0x0005, 0x0006]),
        0x07: ("On/Off Switch", [], [0x0005, 0x0006]),
        0x10: ("Color Dimmer Switch", [], [0x0300]),
        0x11: ("Light Sensor", [0x0400], []),
        0x12: ("Occupancy Sensor", [0x0406], []),
        0x20: ("Door Lock Controller", [], [0x0101]),
        0x30: ("Temperature Sensor", [0x0402], []),
        0x31: ("Pressure Sensor", [0x0403], []),
        0x32: ("Flow Sensor", [0x0404], []),
        0x33: ("Indoor Environment Sensor", [], []),
    }

    def create_device(self, ieee, type=None, remoteCommissioning=False):
        application = self.endpoint.device.application
        if ieee in application.devices:
            return application.devices[ieee]
        if not remoteCommissioning and (
            0x9997 not in self._attr_cache or self._attr_cache[0x9997] < time.time()
        ):
            LOGGER.debug("Not in permit joining mode and not in remoteCommissioning")
            return
        LOGGER.debug("Device %s not found, create it", ieee)
        dev = application.add_device(ieee, 32766)
        dev.status = zigpy.device.Status.ENDPOINTS_INIT
        dev._skip_configuration = True
        dev.node_desc = zdo.types.NodeDescriptor(2, 64, 128, 4174, 82, 82, 0, 82, 0)
        ep = dev.add_endpoint(1)
        ep.status = zigpy.endpoint.Status.ZDO_INIT
        ep.profile_id = zigpy.profiles.zha.PROFILE_ID
        ep.device_type = zigpy.profiles.zha.DeviceType.GREEN_POWER
        ep.add_input_cluster(zigpy.zcl.clusters.general.Basic.cluster_id)
        ep.in_clusters[zigpy.zcl.clusters.general.Basic.cluster_id]._update_attribute(
            0x0004, "GreenPower"
        )
        in_clusters = None
        out_clusters = None
        if type is not None and type in GreenPowerProxy.device:
            name, in_clusters, out_clusters = GreenPowerProxy.device[type]
            ep.in_clusters[
                zigpy.zcl.clusters.general.Basic.cluster_id
            ]._update_attribute(0x0005, name)
            for cluster_id in in_clusters:
                LOGGER.debug("Add input cluster id %s on device %s", cluster_id, ieee)
                ep.add_input_cluster(cluster_id)
            for cluster_id in out_clusters:
                LOGGER.debug("Add output cluster id %s on device %s", cluster_id, ieee)
                ep.add_output_cluster(cluster_id)
        else:
            ep.in_clusters[
                zigpy.zcl.clusters.general.Basic.cluster_id
            ]._update_attribute(0x0005, "GreenPowerDevice")
        ep = dev.add_endpoint(self.endpoint_id)
        ep.status = zigpy.endpoint.Status.ZDO_INIT
        ep.profile_id = zigpy.profiles.zha.PROFILE_ID
        ep.device_type = zigpy.profiles.zha.DeviceType.GREEN_POWER
        ep.add_input_cluster(self.cluster_id)
        application.device_initialized(dev)
        return dev

    def handle_notification(
        self, ieee, header, counter, command_id, payload, payload_length, mic
    ):
        application = self.endpoint.device.application
        if ieee not in application.devices:
            return
        if command_id not in GreenPowerProxy.command:
            LOGGER.debug("Unhandled command_id : %s", command_id)
            return
        calcul_mic = self.calcul_mic(
            ieee,
            header,
            counter,
            command_id.to_bytes(1, "little")
            + payload.to_bytes(payload_length, "little"),
            payload_length + 1,
        )
        if calcul_mic is not None and calcul_mic != mic:
            LOGGER.debug(
                "Wrong mic : %s, calcul mic %s, ignore frame", hex(mic), hex(calcul_mic)
            )
            return
        (
            command,
            type,
            schema,
            cluster_id,
            zcl_command_id,
            value,
        ) = GreenPowerProxy.command[command_id]
        payload, _ = t.deserialize(payload.to_bytes(payload_length, "little"), schema)
        LOGGER.debug(
            "Green power frame ieee : %s, command_id : %s, payload : %s,counter : %s",
            ieee,
            command_id,
            payload,
            counter,
        )
        value = value + tuple(payload)
        dev = application.devices[ieee]
        if counter is not None:
            attributes = (
                dev.endpoints[self.endpoint_id].in_clusters[self.cluster_id]._attr_cache
            )
            if 0x9999 in attributes and attributes[0x9999] >= counter:
                LOGGER.debug("Already get this frame counter,I ignoring it")
                return
            attributes._update_attribute(0x9999, counter)
        if cluster_id is not None and type == "CLUSTER_COMMAND":
            if cluster_id not in dev.endpoints[1].out_clusters:
                dev.endpoints[1].add_output_cluster(cluster_id)
                application.device_initialized(dev)
            dev.endpoints[1].out_clusters[cluster_id].handle_message(
                foundation.ZCLHeader.cluster(
                    application.get_sequence(), zcl_command_id
                ),
                value,
            )

    def handle_message(self, data):
        data = data[0]
        if data[0] == 12 and data[5] == 224:
            ieee = t.EUI64(data[1:5] + data[1:5])
            type = data[6]
            self.create_device(ieee, type)
            return
        payload = ()
        ieee = t.EUI64(data[2:6] + data[2:6])
        counter = int.from_bytes(data[6:10], byteorder="little")
        command_id = data[10]
        payload_length = len(data[11:-4])
        payload = int.from_bytes(data[11:-4], byteorder="little")
        mic = int.from_bytes(data[-4:], byteorder="little")
        header = int.from_bytes(data[0:2], byteorder="little")
        self.handle_notification(
            ieee, header, counter, command_id, payload, payload_length, mic
        )

    def calcul_mic(self, ieee, header, counter, payload, payload_length):
        application = self.endpoint.device.application
        if ieee not in application.devices:
            return None
        dev = application.devices[ieee]
        if (
            0x9998
            not in dev.endpoints[self.endpoint_id]
            .in_clusters[self.cluster_id]
            ._attr_cache
        ):
            return None
        src_id = bytearray(ieee[0:4])
        if not isinstance(header, (bytes)):
            header = header.to_bytes(2, "little")
        if not isinstance(counter, (bytes)):
            counter = counter.to_bytes(4, "little")
        if not isinstance(payload, (bytes)):
            payload = payload.to_bytes(payload_length, "little")
        LOGGER.debug(
            "Calcul mic of green power frame for %s on header : 0x%s, src_id : 0x%s, counter : 0x%s, payload : 0x%s, payload length : %s",
            ieee,
            header.hex(),
            src_id.hex(),
            counter.hex(),
            payload.hex(),
            payload_length,
        )
        key = (
            dev.endpoints[self.endpoint_id]
            .in_clusters[self.cluster_id]
            ._attr_cache[0x9998]
        )
        nonce = src_id + src_id + counter + (0x05).to_bytes(1, "little")
        header = header + src_id + counter
        a = header + payload
        La = len(a).to_bytes(2, "big")
        AddAuthData = La + a
        AddAuthData += (0x00).to_bytes(1, "little") * (16 - len(AddAuthData))
        B0 = (0x49).to_bytes(1, "little") + nonce
        B0 += (0x00).to_bytes(1, "little") * (16 - len(B0))
        B1 = AddAuthData
        X0 = (0x00000000000000000000000000000000).to_bytes(16, "big")
        cipher = AES.new(key, AES.MODE_CBC, B0)
        X1 = cipher.encrypt(X0)
        cipher = AES.new(key, AES.MODE_CBC, B1)
        X2 = cipher.encrypt(X1)
        A0 = (0x01).to_bytes(1, "little") + nonce + (0x0000).to_bytes(2, "big")
        cipher = AES.new(
            key,
            AES.MODE_CTR,
            counter=Counter.new(128, initial_value=int.from_bytes(A0, byteorder="big")),
        )
        return int.from_bytes(cipher.encrypt(X2[0:4]), byteorder="little")

    def setKey(self, key):
        if key is None:
            del self._attr_cache[0x9998]
            return
        if not isinstance(key, (bytes)):
            key = key.to_bytes(16, "big")
        self._update_attribute(0x9998, key)

    async def permit(self, time_s=60):
        assert 0 <= time_s <= 254
        LOGGER.debug("Permit green power pairing for %s s", time_s)
        self._attr_cache[0x9997] = int(time.time() + time_s)
        #tsn = self.endpoint.device.application.get_sequence()
        #hdr = foundation.ZCLHeader.cluster(tsn, 2)  # commissioning
        #hdr.frame_control.disable_default_response = True
        #data = hdr.serialize() + t.serialize((0x0B, time_s), (t.uint8_t, t.uint16_t))
        #return await self.endpoint.device.application.broadcast(
        #    profile=zigpy.profiles.zha.PROFILE_ID,
        #    cluster=self.cluster_id,
        #    src_ep=self.endpoint_id,
        #    dst_ep=self.endpoint_id,
        #    grpid=None,
        #    radius=30,
        #    sequence=tsn,
        #    data=data,
        #)
        return
