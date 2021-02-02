import json
import uuid
import datetime
from NanoCoreAnalyzer.types import NanoCoreType

class NanoCoreJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, NanoCoreType):
            return o.name
        if isinstance(o, bytes):
            return o.hex()
        if isinstance(o, uuid.UUID):
            return str(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat()

        return super(NanoCoreJSONEncoder, self).default(o)