#!/usr/bin/env python3
# vim: ts=2 sts=2 sw=2 et

"""
Extracts assembly templates from the XML.

This file is part of the mra-bi-assembler project of UQ PAC.
"""

import xml.etree.ElementTree as ET
import sys
from pathlib import Path
from dataclasses import dataclass, field

bitpattern = dict[int,bool|None]

def read_field_boxes(path: Path, regdiagram_or_encoding: ET.Element, width: int=-1) -> bitpattern:
  print(path)
  assert regdiagram_or_encoding, path
  bytepattern: dict[int, bool | None] = {}

  for box in regdiagram_or_encoding.findall('box'):
    oldlen = len(bytepattern)
    boxname = box.attrib.get('name', None)
    boxwd = int(box.attrib.get('width', 1))

    lo = int(box.attrib['hibit']) - boxwd + 1
    cs = []
    for c in box.findall('c')[::-1]: # XXX: reverse for least-sig bit first
      t = c.text or ''
      t = t.lstrip('(').rstrip(')')
      t = t if t and t[0].isdigit() else ''
      span = int(c.attrib.get('colspan', '1'))
      if not t:
        assert not t, path
        cs += [None] * span
      else:
        assert t, path
        assert t in ('0', '1')
        cs += [t == '0']
    assert len(cs) == boxwd, f'{len(cs)=} {boxwd=} {path}'

    for i,bit in enumerate(cs):
      bytepattern[lo+i] = bit

  if width >= 0:
    assert len(bytepattern) == width, path

  return bytepattern

@dataclass
class AsmField:
  placeholder: str
  link: str
  hover: str
  intro: str = ''
  after: str = ''
  values: list = field(default_factory=list)

@dataclass
class Asm:
  text: list[str]
  fields: dict[str, AsmField] = field(default_factory=dict)

@dataclass
class InstEnc:
  encname: str
  encfields: bitpattern
  asm: Asm

@dataclass
class InstClass:
  path: Path
  instsection: str  # groups iclasses
  classname: str
  isa: str

  regdiagramfields: bitpattern
  encodings: list[InstEnc]

def read_asmtemplate(path: Path, asmtemplate: ET.Element) -> Asm:
  asmfields = {}
  asm = []
  for asmnode in asmtemplate:
    if asmnode.tag == 'a':
      assert asmnode.text, path
      asm.append(asmnode.text)
      fld = AsmField(asmnode.text, asmnode.attrib['link'], asmnode.attrib['hover'])
      asmfields[fld.link] = fld
    elif asmnode.tag == 'text':
      assert asmnode.text, path
      asm.append(asmnode.text)
  return Asm(asm, asmfields)

def read_inst_enc(path: Path, encoding: ET.Element) -> InstEnc:
  encodingfields = read_field_boxes(path, encoding)
  print(encodingfields)

  asmtemplates = encoding.findall('asmtemplate')
  assert asmtemplates and len(asmtemplates) == 1, f'{asmtemplates=} {path=}'
  asm = read_asmtemplate(path, asmtemplates[0])

  return InstEnc(encoding.attrib['name'], encodingfields, asm)


def read_instruction_xml(path: Path):
  tree = ET.parse(path)
  root = tree.getroot()
  print(path)
  if root.tag != 'instructionsection':
    return

  instructionsection = root.findall('.')
  assert len(instructionsection) == 1, path

  instsection = instructionsection[0].attrib['id']

  for iclass in instructionsection[0].iter('iclass'):
    iclassname = iclass.attrib['id']
    isa = iclass.attrib['isa']

    regdiagram = iclass.find('regdiagram')
    assert regdiagram, path
    regdiagramwidth = int(regdiagram.attrib['form'])
    regdiagramfields = read_field_boxes(path, regdiagram, regdiagramwidth)
    print(regdiagramfields)

    encodings = [read_inst_enc(path, x) for x in iclass.iter('encoding')]
    yield InstClass(path, instsection, iclassname, isa, regdiagramfields, encodings)

def main(indir: Path, outdir: Path):
  # print(list(indir.glob('*.xml')))
  for f in indir.glob('*.xml'):
    # if 'add_addsub_ext.xml' in str(f).lower():
    print(list(read_instruction_xml(f)))

if __name__ == '__main__':
  main(indir=Path(sys.argv[1]), outdir=Path(sys.argv[2]))
