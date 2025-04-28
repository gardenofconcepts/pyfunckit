from datetime import datetime
from functools import wraps
from http import HTTPStatus
from typing import Type

import jwt
from flask import Response
from parliament import Context
from pydantic import BaseModel, Field, ValidationError

from __init__ import logger, JWT_SECRET


class JWTModel(BaseModel):
    issuer: str | None = Field(alias='iss', default=None)
    subject: str | None = Field(alias='sub', default=None)
    name: str | None = Field(alias='name', default=None)
    issued_at: datetime | None = Field(alias='iat', default=None)
    expired_at: datetime | None = Field(alias='exp', default=None)


def require_jwt(func):
    @wraps(func)
    def wrapper(context: Context, *args, **kwargs):
        jwt_value = context.request.headers.get('Authorization', None)

        if jwt_value is None:
            logger.warning('Authorization header missing')
            return {}, HTTPStatus.FORBIDDEN.value

        try:
            data = jwt.decode(jwt_value, key=JWT_SECRET, algorithms=['HS256'])
            token = JWTModel.model_validate(data)
        except jwt.exceptions.InvalidTokenError as e:
            logger.error(f'Error decoding JWT: {e}')
            return {}, HTTPStatus.UNAUTHORIZED.value
        except ValidationError as e:
            logger.error(f'Error validating JWT: {e}')
            return {}, HTTPStatus.BAD_REQUEST.value

        return func(context, token, *args, **kwargs)

    return wrapper


def require_post(func):
    @wraps(func)
    def wrapper(context: Context, *args, **kwargs):
        if context.request.method != "POST":
            logger.warning(f'Request method {context.request.method} not supported')
            return {}, HTTPStatus.METHOD_NOT_ALLOWED.value

        return func(context, *args, **kwargs)

    return wrapper


def require_json(type: Type[BaseModel]):
    def decorator(func):
        @wraps(func)
        def wrapper(context: Context, *args, **kwargs):
            if context.request.headers.get('Content-Type', None) != "application/json":
                logger.warning(f'Request Content-Type {context.request.headers.get("Content-Type")} not supported')
                return {}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE.value

            if context.request.json is None:
                logger.warning('Request body missing')
                return {}, HTTPStatus.BAD_REQUEST.value

            try:
                request = type.model_validate(context.request.json)
            except ValidationError as e:
                logger.exception(f'Request body invalid: {e}')
                return e.json(), HTTPStatus.BAD_REQUEST.value
            except Exception as e:
                logger.exception(f'Error parsing request body: {e}')
                return {}, HTTPStatus.INTERNAL_SERVER_ERROR.value

            response, code = func(context, request, *args, **kwargs)

            if isinstance(response, BaseModel):
                return Response(response.model_dump_json(), mimetype='application/json')

            return response, code

        return wrapper

    return decorator
