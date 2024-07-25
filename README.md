# tuya-fingerbot-micropython

This repository provides code to use CubeTouch or Fingerbot with MicroPython, compatible with ESP32 or similar devices.

## Getting Started

This project is based on the work found [here](https://github.com/redphx/poc-tuya-ble-fingerbot/tree/main).

To extract the necessary information, please use the [Tuya Local Key Extractor](https://github.com/redphx/tuya-local-key-extractor).

## Configuration

For other models, adjust the parameters accordingly. Here are examples for Fingerbot and CubeTouch:

### Fingerbot

Constants:
```
    ARM_DOWN_PERCENT = const(9)
    ARM_UP_PERCENT = const(15)
    CLICK_SUSTAIN_TIME = const(10)
    TAP_ENABLE = const(17)
    MODE = const(8)
    INVERT_SWITCH = const(11)
    TOGGLE_SWITCH = const(2)
    CLICK = const(101)
    PROG = const(121)
```

DPS Message:
```
        dps = [
            [8, DpType.ENUM, 0],
            [DpAction.ARM_DOWN_PERCENT, DpType.INT, 80],
            [DpAction.ARM_UP_PERCENT, DpType.INT, 0],
            [DpAction.CLICK_SUSTAIN_TIME, DpType.INT, 0],
            [DpAction.CLICK, DpType.BOOLEAN, True],
        ]
```
### Cubetouch

Constants:
```
    ARM_DOWN_PERCENT = const(6)
    ARM_UP_PERCENT = const(5)
    CLICK_SUSTAIN_TIME = const(3)
    TAP_ENABLE = const(17)
    MODE = const(2)
    INVERT_SWITCH = const(4)
    TOGGLE_SWITCH = const(1)
    CLICK = const(101)
    PROG = const(121)
```

DPS Message:
```
            dps = [
                [2, DpType.ENUM, 0],
                [DpAction.ARM_DOWN_PERCENT, DpType.INT, 100],
                [DpAction.ARM_UP_PERCENT, DpType.INT, 0],
                [DpAction.CLICK_SUSTAIN_TIME, DpType.INT, 1],
                [DpAction.CLICK, DpType.BOOLEAN, True],
            ]
```

## Additional Resources

For more models, please refer to this [link](https://github.com/PlusPlus-ua/ha_tuya_ble/blob/6037ac5a04ceb23a36d1b88e2303aa1da7fdbe83/custom_components/tuya_ble/devices.py#L238).