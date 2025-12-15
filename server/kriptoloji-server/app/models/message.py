
from dataclasses import dataclass
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
    error: Optional[bool] = None
    
    def to_dict(self) -> dict:
        data = {'type': self.type}
        if self.message is not None:
            data['message'] = self.message
        if self.method is not None:
            data['method'] = self.method
        if self.use_library is not None:
            data['use_library'] = self.use_library
        if self.encrypted_key is not None:
            data['encrypted_key'] = self.encrypted_key
        if self.public_key is not None:
            data['public_key'] = self.public_key
        if self.status is not None:
            data['status'] = self.status
        if self.error is not None:
            data['error'] = self.error
        return data


