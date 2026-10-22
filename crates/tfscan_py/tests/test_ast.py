import gc

import pytest

import tfscan

SRC = '''
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
variable "x" { default = null }
'''


def test_parse_blocks_and_nodes():
    doc = tfscan.parse(SRC)
    assert doc.errors == []
    assert doc.node_count > 10 and doc.arena_bytes > 0
    blocks = doc.blocks()
    assert [b.block_type for b in blocks] == ["resource", "variable"]
    sg = blocks[0]
    assert sg.labels == ["aws_security_group", "web"]
    assert sg.kind == "Block"
    (name,) = sg.attributes()
    assert name.name == "name" and name.value.literal() == "web"
    (ingress,) = sg.blocks()
    attrs = {a.name: a.value for a in ingress.attributes()}
    assert attrs["from_port"].literal() == 22
    assert attrs["cidr_blocks"].kind == "Tuple"
    assert attrs["cidr_blocks"].text == '["0.0.0.0/0"]'
    assert blocks[1].attributes()[0].value.literal() is None
    assert ingress.parent.kind == "Body"
    assert doc.root.kind == "File" and doc.root.parent is None
    assert [n.id for n in doc.walk()] == list(range(doc.node_count))
    with pytest.raises(ValueError):
        sg.literal()


def test_nodes_keep_document_alive():
    doc = tfscan.parse(SRC)
    node = doc.blocks()[0].blocks()[0]
    del doc
    gc.collect()
    assert node.block_type == "ingress"
    assert node.parent.parent.labels == ["aws_security_group", "web"]


def test_parse_recovers_from_errors():
    doc = tfscan.parse('resource "a" "b" {\n  x = \n  y = 1\n}\n')
    assert doc.errors
    (b,) = doc.blocks()
    assert "y" in [a.name for a in b.attributes()]
