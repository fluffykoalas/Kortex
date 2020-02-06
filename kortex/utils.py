# Copyright (c) 2020 Fluffy Koalas open source software. This file is licensed under the MIT license. #


def _check_type(_type, **kwargs):
    for key, val in kwargs.items():
        if not isinstance(val, _type):
            raise TypeError(f'{key} must be {_type}')
