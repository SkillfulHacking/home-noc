# backend/app/api/v1/routers/credentials.py
"""Protected connector-credential API (M04, issue #7).

* Every route requires a session; PUT/DELETE additionally require the CSRF
  token (both enforced by ``require_session`` from M03).
* Secrets travel only in request bodies, never in URLs, and are never
  returned: responses carry a fixed mask plus non-secret metadata.
* Responses are ``Cache-Control: no-store``.
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .... import credentials as svc
from .... import crypto, key_binding, models
from ....credential_schemas import (
    CREDENTIAL_TYPES,
    CredentialList,
    CredentialStatus,
    CredentialWrite,
)
from ....dependencies import get_db
from ....security import require_session

logger = logging.getLogger(__name__)


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


DbDep = Annotated[Session, Depends(get_db)]


def _require_usable_key(db: DbDep) -> None:
    """Fail closed (503) unless the configured key is valid for this database.

    Runs after authentication/CSRF. Gating status reads as well as writes
    means ``configured: true`` is never reported for credentials that the
    current key cannot decrypt. The detail is deliberately generic.
    """
    try:
        key_binding.check_usable(db)
    except crypto.CredentialCryptoError as exc:
        # Exception texts are fixed strings; they never contain key material.
        logger.error("Credential operation refused: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential encryption is not available",
            headers={"Cache-Control": "no-store"},
        ) from None


router = APIRouter(
    prefix="/credentials",
    tags=["credentials"],
    dependencies=[
        Depends(require_session),
        Depends(_no_store),
        Depends(_require_usable_key),
    ],
)
DeviceId = Annotated[str, Path(min_length=1, max_length=36)]
ConnectorName = Annotated[str, Path(pattern=svc.CONNECTOR_NAME_PATTERN)]
TypeName = Annotated[str, Path(min_length=1, max_length=32)]


def _device_scope(db: Session, device_id: str) -> svc.Scope:
    if db.get(models.Device, device_id) is None:
        raise HTTPException(status_code=404, detail="Not found")
    return svc.Scope.device(device_id)


def _spec(scope: svc.Scope, credential_type: str):
    spec = svc.get_spec(credential_type)
    if spec is None or scope.kind not in spec.scopes:
        raise HTTPException(status_code=404, detail="Unknown credential type")
    return spec


def _list(db: Session, scope: svc.Scope) -> CredentialList:
    items = []
    for name, spec in CREDENTIAL_TYPES.items():
        if scope.kind in spec.scopes:
            items.append(svc.to_status(scope, name, svc.find(db, scope, name)))
    return CredentialList(credentials=items)


def _get(db: Session, scope: svc.Scope, credential_type: str) -> CredentialStatus:
    spec = _spec(scope, credential_type)
    return svc.to_status(scope, spec.name, svc.find(db, scope, spec.name))


def _put(
    db: Session,
    response: Response,
    scope: svc.Scope,
    credential_type: str,
    body: CredentialWrite,
) -> CredentialStatus:
    spec = _spec(scope, credential_type)
    try:
        secret_fields, metadata = svc.validate_write(spec, body)
    except svc.CredentialValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors) from None
    try:
        row, created = svc.upsert(db, scope, spec, secret_fields, metadata)
        db.commit()
    except crypto.CredentialCryptoError:
        db.rollback()
        # Generic on purpose: do not hint at which part of the key is wrong.
        logger.error("Credential write refused: encryption is unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential encryption is not available",
        ) from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Credential write conflict"
        ) from None
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    db.refresh(row)
    return svc.to_status(scope, spec.name, row)


def _delete(db: Session, scope: svc.Scope, credential_type: str) -> Response:
    spec = _spec(scope, credential_type)
    svc.delete(db, scope, spec.name)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- device-scoped ---------------------------------------------------------


@router.get("/devices/{device_id}", response_model=CredentialList)
def list_device_credentials(device_id: DeviceId, db: DbDep):
    return _list(db, _device_scope(db, device_id))


@router.get("/devices/{device_id}/{credential_type}", response_model=CredentialStatus)
def get_device_credential(device_id: DeviceId, credential_type: TypeName, db: DbDep):
    return _get(db, _device_scope(db, device_id), credential_type)


@router.put("/devices/{device_id}/{credential_type}", response_model=CredentialStatus)
def put_device_credential(
    device_id: DeviceId,
    credential_type: TypeName,
    body: CredentialWrite,
    response: Response,
    db: DbDep,
):
    return _put(db, response, _device_scope(db, device_id), credential_type, body)


@router.delete("/devices/{device_id}/{credential_type}", status_code=204)
def delete_device_credential(device_id: DeviceId, credential_type: TypeName, db: DbDep):
    return _delete(db, _device_scope(db, device_id), credential_type)


# ---- connector-scoped ------------------------------------------------------


@router.get("/connectors/{connector}", response_model=CredentialList)
def list_connector_credentials(connector: ConnectorName, db: DbDep):
    return _list(db, svc.Scope.connector(connector))


@router.get("/connectors/{connector}/{credential_type}", response_model=CredentialStatus)
def get_connector_credential(connector: ConnectorName, credential_type: TypeName, db: DbDep):
    return _get(db, svc.Scope.connector(connector), credential_type)


@router.put("/connectors/{connector}/{credential_type}", response_model=CredentialStatus)
def put_connector_credential(
    connector: ConnectorName,
    credential_type: TypeName,
    body: CredentialWrite,
    response: Response,
    db: DbDep,
):
    return _put(db, response, svc.Scope.connector(connector), credential_type, body)


@router.delete("/connectors/{connector}/{credential_type}", status_code=204)
def delete_connector_credential(connector: ConnectorName, credential_type: TypeName, db: DbDep):
    return _delete(db, svc.Scope.connector(connector), credential_type)
