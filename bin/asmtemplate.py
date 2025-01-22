#!/usr/bin/env python3
# vim: ts=2 sts=2 sw=2 et

"""
Extracts assembly templates from the XML.

This file is part of the mra-bi-assembler project of UQ PAC.
"""

from collections import defaultdict
from collections.abc import Generator, Iterable
from itertools import chain

import xml.etree.ElementTree as ET
from html import unescape

import sys
import json
import logging
import dataclasses

from pathlib import Path
from dataclasses import dataclass, field

bitpattern = dict[int,bool|None]

logger = logging.getLogger(__name__)

def read_field_boxes(path: Path, regdiagram_or_encoding: ET.Element, width: int=-1) -> dict[str, 'EncField']:
  # print(path)
  assert regdiagram_or_encoding, path
  bytepattern: dict[str, EncField] = {}

  for box in regdiagram_or_encoding.findall('box'):
    oldlen = len(bytepattern)
    boxwd = int(box.attrib.get('width', 1))

    hi = int(box.attrib['hibit'])
    lo = hi - boxwd + 1
    boxname = box.attrib.get('name', f'__hibit{hi}')

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
        cs += [t == '1']
    assert len(cs) == boxwd, f'{len(cs)=} {boxwd=} {path}'

    cspattern = {i+lo:v for i,v in enumerate(cs)}
    bytepattern[boxname] = EncField(boxname, hi, lo, boxwd, cspattern)

  if width >= 0:
    assert sum(x.wd for x in bytepattern.values()) == width, path

  bytepattern = {k:v for k,v in sorted(bytepattern.items(), key=lambda x: -x[1].lo)}
  logger.debug(str(bytepattern))
  return bytepattern

@dataclass
class Assoc:
  link: str  # link to asmfield
  symboltext: str  # text as appears in assembly
  bitfields: dict[str, str]  # map of encfield name to value
  feature: str  # optional feature need for this assoc

@dataclass
class AsmField:
  placeholder: str
  link: str
  hover: str
  intro: str = ''
  after: str = ''
  assocs: list[Assoc] = field(default_factory=list)

@dataclass
class Asm:
  text: list[str]
  asmfields: dict[str, AsmField] = field(default_factory=dict)

@dataclass
class EncField:
  name: str # may be
  hi: int # inclusive
  lo: int # inclusive
  wd: int
  pattern: bitpattern  # keys areabsolute position indices (in the range lo-hi)

@dataclass
class InstEnc:
  encname: str
  instrclass: str
  encfields: dict[str, EncField]
  asm: Asm
  assocs: list[Assoc]

@dataclass
class InstClass:
  path: str
  instsection: str  # groups iclasses
  classname: str
  isa: str

  classfields: dict[str, EncField]
  encodings: dict[str,InstEnc]

def read_asmtemplate(path: Path, asmtemplate: ET.Element) -> Asm:
  logger.info(f'read_asmtemplate {path} {asmtemplate.attrib}')
  asmfields = {}
  asm = []
  for asmnode in asmtemplate:
    if asmnode.tag == 'a':
      assert asmnode.text, path
      asm.append(asmnode.text)
      fld = AsmField(asmnode.text, asmnode.attrib['link'], unescape(asmnode.attrib['hover']))
      asmfields[fld.link] = fld
    elif asmnode.tag == 'text':
      assert asmnode.text, path
      asm.append(asmnode.text)
  return Asm(asm, asmfields)

def read_inst_enc(path: Path, encoding: ET.Element) -> InstEnc:
  logger.info(f'read_inst_enc {path} {encoding.attrib}')
  encodingfields = read_field_boxes(path, encoding)

  asmtemplates = encoding.findall('asmtemplate')
  assert asmtemplates and len(asmtemplates) == 1, f'{asmtemplates=} {path=}'
  asm = read_asmtemplate(path, asmtemplates[0])

  try:
    instrclass = sole(x for x in encoding.iter('docvar') if x.attrib['key'] == 'instr-class').attrib['value']
    assert instrclass, path
  except Exception:
    instrclass = ""
  return InstEnc(encoding.attrib['name'], instrclass, encodingfields, asm, [])


def sole(x, ctx=None):
  xs = list(x)
  assert len(xs) == 1, f'{xs=} {ctx=}'
  return xs[0]

def alltext(e: ET.Element):
  return ' '.join(x for x in (x.text or '' for x in e.iter()) if x).strip()

def read_instruction_xml(path: Path) -> Iterable[InstClass]:
  logger.info(f'read_instruction_xml {path}')
  tree = ET.parse(path)
  root = tree.getroot()
  if root.tag != 'instructionsection':
    return []

  instructionsection = root.findall('.')
  assert len(instructionsection) == 1, path

  instsection = instructionsection[0].attrib['id']

  iclasses: list[InstClass] = []
  for iclass in instructionsection[0].iter('iclass'):
    iclassname = iclass.attrib['id']
    isa = iclass.attrib['isa']

    regdiagram = iclass.find('regdiagram')
    assert regdiagram, path
    regdiagramwidth = int(regdiagram.attrib['form'])
    regdiagramfields = read_field_boxes(path, regdiagram, regdiagramwidth)
    logger.debug(str(regdiagramfields))

    enclist = [read_inst_enc(path, x) for x in iclass.iter('encoding')]
    encodings = {x.encname: x for x in enclist}
    iclasses.append(InstClass(str(path), instsection, iclassname, isa, regdiagramfields, encodings))

  expldata = defaultdict(list)
  for expls in instructionsection[0].iter('explanations'):
    assert expls.attrib['scope'] == 'all', path

    for expl in expls.iter('explanation'):
      symbol = sole(expl.iter('symbol'))
      link = symbol.attrib['link']
      enclist = expl.attrib['enclist'].split(', ')
      defn = sole(chain(expl.iter('definition'), expl.iter('account')))

      intro = sole(defn.iter('intro'))
      introtext = alltext(intro)
      assert introtext, path

      after = list(defn.iter('after'))
      assert len(after) <= 1, path
      after = alltext(after[0]) if after else ''

      tables = defn.findall('table')
      assert len(tables) <= 1
      options = []
      if tables and (tbl := tables[0]):
        keys = [x.text or '' for x in sole(tbl.iter('thead')).iter('entry') if x.attrib['class'] == 'bitfield']
        if 'Description' in keys:
          keys.remove('Description')
        assert all(keys), path

        for row in sole(tbl.iter('tbody')).iter('row'):
          childs = [x for x in row if x.attrib['class'] not in ('description', )]

          sym = sole(x.text for x in row if x.attrib['class'] == 'symbol')
          assert sym, path

          flds = [x.text or '' for x in row if x.attrib['class'] == 'bitfield']
          assert all(flds), path
          assert len(flds) == len(keys), path

          feats = [x.text or '' for x in row if x.attrib['class'] == 'feature']
          assert len(feats) <= 1, path

          # print(ET.tostring(row))
          assert 1 + len(flds) + len(feats) == len(childs), path

          assoc = Assoc(link, sym, {k:v for k,v in zip(keys, flds)}, feats[0] if feats else '')

          options.append(assoc)

      row = (link, introtext, after, options)
      logger.debug(f'assoc row: {row}')

      link = symbol.attrib['link']
      for encname in enclist:
        expldata[encname].append(row)

  for iclass in iclasses:
    for ienc in iclass.encodings.values():
      expls = expldata[ienc.encname]
      for (link, intro, after, options) in expls:
        asmfield = ienc.asm.asmfields[link]
        asmfield.intro = intro
        asmfield.after = after
        asmfield.assocs = options

  return iclasses

def main(indir: Path, outdir: Path):
  # print(list(indir.glob('*.xml')))
  out = []
  for f in indir.glob('*.xml'):
    # if 'add_addsub_ext.xml' not in str(f).lower():
    #   continue
    try:
      for iclass in read_instruction_xml(f):
        out.append(iclass)
    except:
      print('EXCEPTION RAISED IN', f)
      raise

  outf = 'out.json'
  with open(outf, 'w') as f:
    json.dump([dataclasses.asdict(x) for x in out], f, indent=2)
  logger.info(f'wrote to {outf}')

if __name__ == '__main__':
  logging.basicConfig(format='[%(levelname)s] [%(funcName)s:%(lineno)s] %(message)s', level=logging.DEBUG)
  main(indir=Path(sys.argv[1]), outdir=Path(sys.argv[2]))
