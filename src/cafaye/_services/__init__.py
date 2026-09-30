"""Typed service clients, one module per service that has a document.

``identity`` is here and is the whole of it. Five more services have documents,
and adding them is a module plus a property plus a row in
``tests/test_services.py`` — deliberately additive and deliberately **not**
pending work this packet had no time for.

The rule that makes adding one cheap is that a service module declares its
operations in a table and writes each one twice: once synchronously and once as a
coroutine. A service module that grew a method on only one face fails
``tests/test_identity.py``'s parity assertion, in the place where the omission is.
"""

from __future__ import annotations

from .identity import AsyncIdentityService, IdentityService

__all__ = ["AsyncIdentityService", "IdentityService"]