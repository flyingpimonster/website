import base64
import datetime
import hashlib
import logging
from enum import Enum
from typing import Annotated

import jwt
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi_sqlalchemy import db as sqldb
from pydantic import BaseModel
from requests.auth import HTTPBasicAuth

from . import config, models, utils, worker
from .emails import EmailCategory, EmailInfo
from .logins import login_state

router = APIRouter(prefix="/upload-tokens")


class ErrorDetail(str, Enum):
    # The flat-manager endpoint is not configured
    FLAT_MANAGER_NOT_CONFIGURED = "flat_manager_not_configured"
    # flat-manager returned an error
    FLAT_MANAGER_ERROR = "flat_manager_error"
    # The user is not a developer of the app
    NOT_APP_DEVELOPER = "not_app_developer"
    # One or more of the requested scopes is not allowed
    FORBIDDEN_SCOPE = "forbidden_scope"
    # One or more of the requested repos is not allowed
    FORBIDDEN_REPO = "forbidden_repo"
    # May not create upload tokens for the stable repo for apps with a github.com/flathub repository
    NOT_DIRECT_UPLOAD_APP = "not_direct_upload_app"
    # The token was not found
    TOKEN_NOT_FOUND = "token_not_found"


class TokenResponse(BaseModel):
    id: int
    comment: str

    app_id: str
    scopes: list[str]
    repos: list[str]

    issued_at: int
    issued_to: str | None
    expires_at: int
    revoked: bool


class NewTokenResponse(BaseModel):
    token: str
    details: TokenResponse


class TokensResponse(BaseModel):
    tokens: list[TokenResponse]
    is_direct_upload_app: bool


def _token_response(token: models.UploadToken, issued_to: str | None) -> TokenResponse:
    return TokenResponse(
        id=token.id,
        comment=token.comment,
        app_id=token.app_id,
        scopes=token.scopes.split(" "),
        repos=token.repos.split(" "),
        issued_at=int(token.issued_at.timestamp()),
        issued_to=issued_to,
        expires_at=int(token.expires_at.timestamp()),
        revoked=token.revoked,
    )


_JTI_PREFIX = "backend_"


def _jti(token: models.UploadToken) -> str:
    return f"{_JTI_PREFIX}{token.id}"


@router.get("/{app_id}", status_code=200)
def get_upload_tokens(
    app_id: str, include_expired: bool = False, login=Depends(login_state)
) -> TokensResponse:
    """
    Get all upload tokens for the given app
    """

    if app_id not in login["user"].dev_flatpaks(sqldb):
        raise HTTPException(status_code=403, detail=ErrorDetail.NOT_APP_DEVELOPER)

    direct_upload_app = models.DirectUploadApp.by_app_id(sqldb, app_id)

    tokens = (
        sqldb.session.query(models.UploadToken, models.FlathubUser.display_name)
        .join(models.FlathubUser)
        .filter(models.UploadToken.app_id == app_id)
    )

    if not include_expired:
        tokens = tokens.filter(
            models.UploadToken.expires_at >= datetime.datetime.utcnow()
        )

    tokens = tokens.order_by(models.UploadToken.issued_at.desc())

    return TokensResponse(
        tokens=[_token_response(t, display_name) for t, display_name in tokens],
        is_direct_upload_app=(direct_upload_app is not None),
    )


ALLOWED_SCOPES = ["build", "upload", "publish"]
ALLOWED_REPOS = ["stable", "beta"]


class UploadTokenRequest(BaseModel):
    comment: str
    scopes: list[str]
    repos: list[str]


@router.post("/{app_id}", status_code=200)
def create_upload_token(
    app_id: str,
    request: UploadTokenRequest,
    login=Depends(login_state),
) -> NewTokenResponse:
    if config.settings.flat_manager_api is None:
        raise HTTPException(
            status_code=500,
            detail=ErrorDetail.FLAT_MANAGER_NOT_CONFIGURED,
        )

    if app_id not in login["user"].dev_flatpaks(sqldb):
        raise HTTPException(status_code=403, detail=ErrorDetail.NOT_APP_DEVELOPER)

    if "stable" in request.repos:
        # Only direct upload apps may create tokens for the stable repo.
        direct_upload_app = models.DirectUploadApp.by_app_id(sqldb, app_id)
        if direct_upload_app is None:
            raise HTTPException(
                status_code=403,
                detail=ErrorDetail.NOT_DIRECT_UPLOAD_APP,
            )

    if not all(s in ALLOWED_SCOPES for s in request.scopes):
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail.FORBIDDEN_SCOPE,
        )

    if not all(r in ALLOWED_REPOS for r in request.repos):
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail.FORBIDDEN_REPO,
        )

    issued_at = datetime.datetime.utcnow()
    issued_to = login["user"]
    expires_at = issued_at + datetime.timedelta(days=180)

    # Create the row in the database
    token = models.UploadToken(
        comment=request.comment,
        app_id=app_id,
        scopes=" ".join(request.scopes),
        repos=" ".join(request.repos),
        issued_at=issued_at,
        issued_to=issued_to.id,
        expires_at=expires_at,
    )
    sqldb.session.add(token)
    sqldb.session.commit()

    worker.send_email.send(
        EmailInfo(
            app_id=app_id,
            category=EmailCategory.UPLOAD_TOKEN_CREATED,
            subject="New upload token issued",
            template_data={
                "issued_to": issued_to.display_name,
                "comment": request.comment,
                "scopes": request.scopes,
                "repos": request.repos,
                "expires_at": expires_at.strftime("%-d %B %Y"),
                "token_id": _jti(token),
            },
        ).dict()
    )

    # Create the JWT
    encoded = jwt.encode(
        {
            "jti": _jti(token),
            "sub": "build",
            "scope": request.scopes,
            "repos": request.repos,
            "prefixes": [app_id],
            "iat": issued_at,
            "exp": expires_at,
        },
        base64.b64decode(config.settings.flat_manager_build_secret),
        algorithm="HS256",
    )

    if config.settings.flat_manager_build_token_prefix is not None:
        encoded = config.settings.flat_manager_build_token_prefix + encoded

    return NewTokenResponse(
        token=encoded,
        details=_token_response(token, issued_to.display_name),
    )


def _revoke_token(jti: str):
    """Sends the request to flat-manager to revoke the token"""
    flat_manager_jwt = utils.create_flat_manager_token(
        "revoke_upload_token", ["tokenmanagement"], sub=""
    )

    response = requests.post(
        config.settings.flat_manager_api + "/api/v1/tokens/revoke",
        headers={"Authorization": flat_manager_jwt},
        json={"token_ids": [jti]},
    )
    if not response.ok:
        raise HTTPException(
            status_code=500,
            detail=ErrorDetail.FLAT_MANAGER_ERROR,
        )


@router.post("/{token_id}/revoke", status_code=204)
def revoke_upload_token(token_id: int, login=Depends(login_state)):
    if config.settings.flat_manager_api is None:
        raise HTTPException(
            status_code=500,
            detail=ErrorDetail.FLAT_MANAGER_NOT_CONFIGURED,
        )

    token = models.UploadToken.by_id(sqldb, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail=ErrorDetail.TOKEN_NOT_FOUND)

    if token.app_id not in login["user"].dev_flatpaks(sqldb):
        raise HTTPException(
            status_code=403,
            detail=ErrorDetail.NOT_APP_DEVELOPER,
        )

    _revoke_token(_jti(token))

    token.revoked = True
    sqldb.session.commit()


secret_scanning_router = APIRouter(prefix="/secret-scanning")


class SecretScanningToken(BaseModel):
    token: str
    type: str
    url: str
    source: str


class SecretScanningTokenLabel(str, Enum):
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"


class SecretScanningTokenResponse(BaseModel):
    token_hash: str
    token_type: str
    label: SecretScanningTokenLabel


async def get_body(request: Request):
    return await request.body()


@secret_scanning_router.post("/notify")
def secret_scanning(
    tokens: list[SecretScanningToken],
    github_public_key_identifier: Annotated[str | None, Header()],
    github_public_key_signature: Annotated[str | None, Header()],
    body: bytes = Depends(get_body),
):
    # Get the public keys from GitHub
    response = requests.get(
        "https://api.github.com/meta/public_keys/secret_scanning",
        auth=HTTPBasicAuth(
            config.settings.github_client_id, config.settings.github_client_secret
        ),
    )

    if not response.ok:
        raise HTTPException(status_code=500, detail="Could not fetch public keys")

    # Verify the signature
    json = response.json()

    keys = [
        key["key"]
        for key in json["public_keys"]
        if key["key_identifier"] == github_public_key_identifier
    ]
    if len(keys) != 1:
        raise HTTPException(status_code=400, detail="Invalid key identifier")

    public_key = load_pem_public_key(keys[0].encode("utf-8"), default_backend())
    signature = base64.b64decode(github_public_key_signature)

    try:
        public_key.verify(signature, body, ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Invalid signature")

    responses = []
    for token in tokens:
        response = SecretScanningTokenResponse(
            token_hash=hashlib.sha256(token.token.encode("utf-8")).hexdigest(),
            token_type=token.type,
            label=SecretScanningTokenLabel.TRUE_POSITIVE,
        )

        token_text = token.token
        if prefix := config.settings.flat_manager_build_token_prefix:
            token_text = token_text.removeprefix(prefix)

        # Decode the JWT
        try:
            decoded = jwt.decode(
                token_text,
                base64.b64decode(config.settings.flat_manager_build_secret),
                algorithms=["HS256"],
            )
        except jwt.exceptions.InvalidTokenError:
            response.label = SecretScanningTokenLabel.FALSE_POSITIVE
            responses.append(response)
            continue

        # Revoke the token
        if jti := decoded.get("jti"):
            token_id = int(jti.removeprefix(_JTI_PREFIX))

            if upload_token := models.UploadToken.by_id(sqldb, token_id):
                if upload_token.revoked:
                    responses.append(response)
                    continue

                upload_token.revoked = True
                sqldb.session.commit()

                worker.send_email.send(
                    EmailInfo(
                        app_id=upload_token.app_id,
                        category=EmailCategory.UPLOAD_TOKEN_AUTO_REVOKED,
                        subject="Upload token found in public repository and revoked",
                        template_data={
                            "token_id": jti,
                            "comment": upload_token.comment,
                            "scopes": upload_token.scopes.split(" "),
                            "repos": upload_token.repos.split(" "),
                            "source": token.source,
                            "url": token.url,
                        },
                    ).dict()
                )
            else:
                logging.error(
                    f"Secret scanning notified us of a leaked token ({jti}) which is valid, but we have no record of it in the database! We will still tell flat-manager to revoke it."
                )

            _revoke_token(jti)
        else:
            logging.error(
                "WARNING! Secret scanning notified us of a leaked token which is valid, but has no jti claim! We cannot tell flat-manager to revoke it because there is no identifier."
            )

        responses.append(response)

    return responses


def register_to_app(app: FastAPI):
    """
    Register the login and authentication flows with the FastAPI application
    """
    app.include_router(router)
    app.include_router(secret_scanning_router)
