from construct.core import Struct, Int16ub

difuse_request = Struct(
        op=Int16ub,
        length=Int16ub,
    )

difuse_response = Struct(
        status=Int16ub,
        length=Int16ub)
