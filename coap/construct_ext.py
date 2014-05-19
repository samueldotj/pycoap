"""
This file contains all the functions used to extend constrct library.
"""
from construct import *


class RepeatUntilExclude(Subconstruct):
    r"""
    Similar to Construct.RepeatUntil() except the delimiter is not included in the output.
    """
    __slots__ = ["predicate"]
    def __init__(self, predicate, subcon):
        Subconstruct.__init__(self, subcon)
        self.predicate = predicate
        self._clear_flag(self.FLAG_COPY_CONTEXT)
        self._set_flag(self.FLAG_DYNAMIC)

    def _parse(self, stream, context):
        obj = []
        try:
            if self.subcon.conflags & self.FLAG_COPY_CONTEXT:
                while True:
                    subobj = self.subcon._parse(stream, context.__copy__())
                    if self.predicate(subobj, context):
                        break
                    obj.append(subobj)
            else:
                while True:
                    subobj = self.subcon._parse(stream, context)
                    if self.predicate(subobj, context):
                        break
                    obj.append(subobj)
        except ConstructError:
            pass
            #raise ArrayError("missing terminator", sys.exc_info()[1])
        return obj

    def _build(self, obj, stream, context):
        if self.subcon.conflags & self.FLAG_COPY_CONTEXT:
            for subobj in obj:
                if self.predicate(subobj, context):
                    break
                self.subcon._build(subobj, stream, context.__copy__())
        else:
            for subobj in obj:
                if self.predicate(subobj, context):
                    break
                self.subcon._build(subobj, stream, context.__copy__())

    def _sizeof(self, context):
        raise SizeofError("can't calculate size")


