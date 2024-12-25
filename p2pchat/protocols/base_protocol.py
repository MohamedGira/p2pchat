class BaseResponse:
    def __init__(self, success_codes, failure_codes):
        self.success_codes = success_codes
        self.failure_codes = failure_codes
        self.all_codes = {**self.success_codes, **self.failure_codes}

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "is_success": self.is_success,
            "data": self.data,
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(data["code"], data["message"], data["is_success"], data["data"])
