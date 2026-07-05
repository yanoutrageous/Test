from __future__ import annotations


def create_app(*args, **kwargs):
    from .web import create_app as create_flask_app

    return create_flask_app(*args, **kwargs)

__all__ = ["create_app"]
