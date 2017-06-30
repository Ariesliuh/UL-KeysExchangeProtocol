#!/usr/bin/env python
# -*- coding=utf-8 -*-
# protocol.py

from enum import Enum

class Protocol_Type(Enum):
    TEXT = 1
    FILE = 2
    PROTOCOL = 3
    COMMAND = 4
