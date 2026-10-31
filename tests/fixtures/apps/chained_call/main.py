import vulnlib


def main(data):
    # The vulnerable call is the receiver of another call.
    return vulnlib.unsafe_parse(data).strip()


def size(data):
    # And the receiver of an attribute read.
    return vulnlib.unsafe_parse(data).__class__
