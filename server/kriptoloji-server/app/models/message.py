from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class MessagePacket:
    type: str
    message: Optional[str] = None
    method: Optional[str] = None
    use_library: Optional[bool] = None
    encrypted_key: Optional[str] = None
    public_key: Optional[str] = None
    status: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}