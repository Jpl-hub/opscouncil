from __future__ import annotations

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except ImportError:  # pragma: no cover - exercised with pydantic v1 runtimes
    from pydantic import BaseModel as _BaseModel
    from pydantic import Field as _Field
    from pydantic import ValidationError, validator

    class BaseModel(_BaseModel):
        @classmethod
        def model_validate(cls, value):
            return cls.parse_obj(value)

        @classmethod
        def model_json_schema(cls, *args, **kwargs):
            return cls.schema()

        def model_dump(self, mode: str | None = None, **kwargs):
            return self.dict(**kwargs)

        def model_copy(self, update=None, **kwargs):
            return self.copy(update=update, **kwargs)

    def Field(*args, pattern: str | None = None, **kwargs):
        if pattern is not None and "regex" not in kwargs:
            kwargs["regex"] = pattern
        return _Field(*args, **kwargs)

    def field_validator(*fields, mode: str = "after", **kwargs):
        kwargs.pop("mode", None)
        kwargs.setdefault("allow_reuse", True)
        return validator(*fields, pre=(mode == "before"), **kwargs)
