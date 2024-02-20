#!/usr/bin/env python3

'''
Unpack ARM System Register XML files creating ASL type definitions.
'''

import argparse, glob, os, re, sys
import xml.etree.cElementTree as ET

# Workaround.
# The following registers are described as 64-bit in the XML files
# but they are treated as 32-bit in the ASL files.
# The workaround is to generate 32-bit variables even though they are
# declared as 64-bit registers.
regs32 = [
    "AFSR0_EL1",
    "AFSR0_EL2",
    "AFSR0_EL3",
    "AFSR1_EL1",
    "AFSR1_EL2",
    "AFSR1_EL3",
    "AIDR_EL1",
    "CCSIDR2_EL1",
    "CCSIDR_EL1",
    "CNTFRQ_EL0",
    "CNTHPS_CTL_EL2",
    "CNTHPS_TVAL_EL2",
    "CNTHP_CTL_EL2",
    "CNTHP_TVAL_EL2",
    "CNTHVS_CTL_EL2",
    "CNTHVS_TVAL_EL2",
    "CNTHV_CTL_EL2",
    "CNTHV_TVAL_EL2",
    "CNTPS_CTL_EL1",
    "CNTPS_TVAL_EL1",
    "CNTP_CTL_EL0",
    "CNTP_TVAL_EL0",
    "CNTV_CTL_EL0",
    "CNTV_TVAL_EL0",
    "CONTEXTIDR_EL1",
    "CONTEXTIDR_EL2",
    "CPTR_EL3",
    "CSSELR_EL1",
    "CURRENTEL",
    "DACR32_EL2",
    "DAIF",
    "DBGAUTHSTATUS_EL1",
    "DBGBCRN_EL1",
    "DBGCLAIMCLR_EL1",
    "DBGCLAIMSET_EL1",
    "DBGPRCR_EL1",
    "DBGVCR32_EL2",
    "DBGWCRN_EL1",
    "DCZID_EL0",
    "DIT",
    "FPEXC32_EL2",
    "FPSR",
    "HACR_EL2",
    "HSTR_EL2",
    "ICC_AP0RN_EL1",
    "ICC_AP1RN_EL1",
    "ICC_BPR0_EL1",
    "ICC_BPR1_EL1",
    "ICC_CTLR_EL1",
    "ICC_CTLR_EL3",
    "ICC_DIR_EL1",
    "ICC_EOIR0_EL1",
    "ICC_EOIR1_EL1",
    "ICC_HPPIR0_EL1",
    "ICC_HPPIR1_EL1",
    "ICC_IAR0_EL1",
    "ICC_IAR1_EL1",
    "ICC_IGRPEN0_EL1",
    "ICC_IGRPEN1_EL1",
    "ICC_IGRPEN1_EL3",
    "ICC_PMR_EL1",
    "ICC_RPR_EL1",
    "ICC_SRE_EL1",
    "ICC_SRE_EL2",
    "ICC_SRE_EL3",
    "ICH_AP0RN_EL2",
    "ICH_AP1RN_EL2",
    "ICH_EISR_EL2",
    "ICH_ELRSR_EL2",
    "ICH_HCR_EL2",
    "ICH_MISR_EL2",
    "ICH_VMCR_EL2",
    "ICH_VTR_EL2",
    "ICV_AP0RN_EL1",
    "ICV_AP1RN_EL1",
    "ICV_BPR0_EL1",
    "ICV_BPR1_EL1",
    "ICV_CTLR_EL1",
    "ICV_DIR_EL1",
    "ICV_EOIR0_EL1",
    "ICV_EOIR1_EL1",
    "ICV_HPPIR0_EL1",
    "ICV_HPPIR1_EL1",
    "ICV_IAR0_EL1",
    "ICV_IAR1_EL1",
    "ICV_IGRPEN0_EL1",
    "ICV_IGRPEN1_EL1",
    "ICV_PMR_EL1",
    "ICV_RPR_EL1",
    "ID_AFR0_EL1",
    "ID_DFR0_EL1",
    "ID_ISAR0_EL1",
    "ID_ISAR1_EL1",
    "ID_ISAR2_EL1",
    "ID_ISAR3_EL1",
    "ID_ISAR4_EL1",
    "ID_ISAR5_EL1",
    "ID_ISAR6_EL1",
    "ID_MMFR0_EL1",
    "ID_MMFR1_EL1",
    "ID_MMFR2_EL1",
    "ID_MMFR3_EL1",
    "ID_MMFR4_EL1",
    "ID_PFR0_EL1",
    "ID_PFR1_EL1",
    "ID_PFR2_EL1",
    "IFSR32_EL2",
    "ISR_EL1",
    "MDCCINT_EL1",
    "MDCCSR_EL0",
    "MDSCR_EL1",
    "MIDR_EL1",
    "MVFR0_EL1",
    "MVFR1_EL1",
    "MVFR2_EL1",
    "NZCV",
    "OSDLR_EL1",
    "OSDTRRX_EL1",
    "OSDTRTX_EL1",
    "OSECCR_EL1",
    "OSLAR_EL1",
    "OSLSR_EL1",
    "PAN",
    "PMCCFILTR_EL0",
    "PMCNTENCLR_EL0",
    "PMCNTENSET_EL0",
    "PMEVCNTRN_EL0",
    "PMEVTYPERN_EL0",
    "PMINTENCLR_EL1",
    "PMINTENSET_EL1",
    "PMOVSCLR_EL0",
    "PMOVSSET_EL0",
    "PMSELR_EL0",
    "PMSWINC_EL0",
    "PMUSERENR_EL0",
    "PMXEVCNTR_EL0",
    "PMXEVTYPER_EL0",
    "REVIDR_EL1",
    "RMR_EL1",
    "RMR_EL2",
    "RMR_EL3",
    "RMUID_EL0",
    "SDER32_EL2",
    "SDER32_EL3",
    "SPSEL",
    "SSBS",
    "UAO",
    "VPIDR_EL2",
    ]
olderregs32 = [
    "CNTHCTL_EL2",
    "CNTKCTL_EL1",
    "CPACR_EL1",
    "CPTR_EL2",
    "CTR_EL0",
    "DBGDTRRX_EL0",
    "DBGDTRTX_EL0",
    "DSPSR_EL0",
    "ESR_EL0",
    "ESR_EL1",
    "ESR_EL2",
    "ESR_EL3",
    "FPCR",
    "MDCR_EL2",
    "MDCR_EL3",
    "PMCR_EL0",
    "RGSR_EL1",
    "SPSR_abt",
    "SPSR_EL0",
    "SPSR_EL1",
    "SPSR_EL2",
    "SPSR_EL3",
    "SPSR_fiq",
    "SPSR_irq",
    "SPSR_und",
    "TCR_EL3",
    "VSTCR_EL2",
    "VTCR_EL2",
    # Morello
    "CCTLR_EL0",
    "CCTLR_EL1",
    "CCTLR_EL2",
    "CCTLR_EL3",
    ]

# Collapse secure/non-secure registers into a single definition
# We currently don't have definitions for the two variants, not sure where to pull this from
regsSecure = [
    'ICC_BPR1_EL1',
    'ICC_SRE_EL1',
    'ICC_AP1R_EL1',
    'ICC_IGRPEN1_EL1',
    'ICC_CTLR_EL1',
]

# Cases with syntatic issues, ignore for now
problematic = [
    'AMEVTYPER1_EL0', 
    'AMEVCNTR0_EL0',
    'AMEVCNTR1_EL0'
]

def parseBin(s):
    res = re.match('0b([01x]+)(.*)', s)
    if res:
        return (res[1], res[2])
    return None

def parseBit(s):
    res = re.match('([^\[])*\[(\d+)](.*)', s)
    if res:
        return ("x", res[3])
    return None

def parseRange(s):
    res = re.match('([^\[])*\[(\d+):(\d+)\](.*)', s)
    if res:
        width = int(res[2]) - int(res[3]) + 1
        return ("x" * width, res[4])
    return None

def parsePattern(s):
    out = ""
    fns = [parseBin, parseBit, parseRange]
    while len(s) > 0:
        if s[0] == ":":
            s = s[1:]
        match = False
        for f in fns:
            m = f(s)
            if m:
                out += m[0]
                s = m[1]
                match = True
                break
        if not match:
            print("Failed to match pattern: " + s)
            return None
    return out

# Pulled from instrs2asl.py, patching the slice format
def patchSlices(x):
    reIndex = r'[0-9a-zA-Z_+*:\-()[\]., ]+'
    rePart = reIndex
    reParts = rePart+"(,"+rePart+")*"
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    return x

# Access mechanisms refer to an arbitrary register t, however,
# the ASL specification expects to pass in and extract an arbitrary value.
# Patch the reads and writes to register t with the value.
def patchIO(x):
    x = x.replace(" X[t, 64] = ", " return ")
    x = x.replace("X[t]", "val")
    return x

# Some registers appear to be duplicated into secure and non-secure forms.
# However, only a single instance is currently created.
# For now, simply alias the two.
def patchSecureRegisters(x):
    for r in regsSecure:
        x = x.replace(r + '_S', r)
        x = x.replace(r + '_NS', r)
    return x

# Pad reads and slice writes when accessing registers in the regs32 array.
# Fortunately, these accesses are generally trivial and can be easily modified.
def patchRegisterWidths(x):
    for r in regs32:
        x = x.replace('return ' + r + ';', 'return Zeros(32):' + r + ';')
        x = x.replace(' ' + r + ' = val;', ' ' + r + ' = val[31:0];')
    return x

# SysReg definitions use a function to test for implementation features.
# Rewrite into an access to IMPLEMENTATION_DEFINED flags.
def patchFeatureImpl(x):
    x = re.sub("IsFeatureImplemented\((\"[^\)]*\")\)", r'boolean IMPLEMENTATION_DEFINED \1', x)
    return x

def patchAll(x):
    x = patchSlices(x)
    x = patchIO(x)
    x = patchSecureRegisters(x)
    x = patchRegisterWidths(x)
    x = patchFeatureImpl(x)
    return x

def readName(n):
    n = n.replace('<','')
    n = n.replace('>','')
    return n + '_reg_read'

def readDecl(n):
    return "bits(64) " +  readName(n) + '(integer op0, integer op1, integer CRn, integer CRm, integer op2)'

def readCall(n):
    return readName(n) + '(op0, op1, CRn, CRm, op2)'

def writeName(n):
    n = n.replace('<','')
    n = n.replace('>','')
    return n + '_reg_write'

def writeDecl(n):
    return writeName(n) + '(integer op0, integer op1, integer CRn, integer CRm, integer op2, bits(64) val)'

def writeCall(n):
    return writeName(n) + '(op0, op1, CRn, CRm, op2, val[63:0])'

sysRegRead = []
sysRegWrite = []

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', '-v', help='Use verbose output',
                        action = 'store_true')
    parser.add_argument('--output', '-o', help='Basename for output files',
                        metavar='FILE', default='regs')
    parser.add_argument('dir', metavar='<dir>',  nargs='+',
                        help='input directory')
    parser.add_argument('--older32', help='Treat more registers as 32-bits for older ASL',
                        action = 'store_true')
    args = parser.parse_args()

    if args.older32:
        regs32.extend(olderregs32)

    # read all the registers
    regs = {}
    for d in args.dir:
        for f in glob.glob(os.path.join(d, '*.xml')):
            filename = f
            xml = ET.parse(f)
            for r in xml.iter('register'):
                if r.attrib['is_register'] == 'True':
                    long = r.find('reg_long_name').text
                    name = r.find('reg_short_name').text
                    if name == 'LSR':
                        # The name of the LSR register conflicts with the LSR
                        # function.  Since LSR is not referred to in the current
                        # ASL, the simplest workaround is to omit the LSR register but
                        # another solution will be needed in the long run.
                        print("Workaround: Skipping LSR register")
                        continue
                    bounds = None
                    if r.find('reg_array'):
                        lo = r.find('reg_array/reg_array_start').text
                        hi = r.find('reg_array/reg_array_end').text
                        bounds = (lo,hi)
                        name = name.replace("<n>","")
                    # there can be multiple views of a register each either 32 or 64 bits
                    # so take the longest.  (Required for TTBR0/1)
                    length = max([int(l.attrib['length']) for l in r.findall('reg_fieldsets/fields') ])
                    if name in regs32:
                        # workaround: even if the register is 64-bit, treat it as 32-bit
                        # if it is on the regs32 list
                        length = 32
                    fields = {}
                    slices = {}
                    for f in r.findall('reg_fieldsets/fields/field'):
                        if f.find('field_name') is not None:
                            nm = f.find('field_name').text
                            if nm == "VMID" and name in ['EDVIDSR', 'PMVIDSR']: nm = "VMID[7:0]" # workaround
                            slice = None
                            m1 = re.match('^(\w+)\[(\d+)\]$', nm)
                            m2 = re.match('^(\w+)\[(\d+):(\d+)\]$', nm)
                            if m1:
                                nm = m1.group(1)
                                hi = m1.group(2)
                                slice = (hi,hi)
                            elif m2:
                                nm = m2.group(1)
                                hi = m2.group(2)
                                lo = m2.group(3)
                                slice = (hi,lo)
                            msb = f.find('field_msb').text
                            lsb = f.find('field_lsb').text
                            isident = (re.match('^[a-zA-Z_]\w*$', nm)
                                       and nm != "UNKNOWN")
                            if slice:
                                if nm not in slices: slices[nm] = []
                                slices[nm].append((msb,lsb,slice))
                            elif isident:
                                if f.find('field_rangesets') is not None:
                                    if nm not in fields: fields[nm] = []
                                    for rs in f.findall('field_rangesets/field_rangeset'):
                                        msb = rs.find('field_msb').text
                                        lsb = rs.find('field_lsb').text
                                        fields[nm].append((msb, lsb))
                                else:
                                    fields[nm] = [(msb,lsb)]
                            else:
                                # print(name,nm)
                                pass

                    a = r.find('access_mechanisms')
                    if a:
                        for mech in a.findall('access_mechanism'):
                            if 'accessor' in mech.attrib:
                                accname = mech.attrib['accessor']
                                if accname.startswith("MRS "):
                                    tests = { enc.attrib['n']: enc.attrib['v'] for enc in mech.findall('encoding/enc')}
                                    body = mech.findall('access_permission/ps/pstext')
                                    if not name in problematic:
                                        sysRegRead.append((name,tests,body[0].text))
                                elif accname.startswith("MSRregister "):
                                    tests = { enc.attrib['n']: enc.attrib['v'] for enc in mech.findall('encoding/enc')}
                                    body = mech.findall('access_permission/ps/pstext')
                                    sysRegWrite.append((name,tests,body[0].text))

                    for f in slices.keys():
                        # If another field element gave a rangeset then we don't need name-based slices
                        if f in fields: continue

                        ss = slices[f]
                        ss.sort(key=lambda s: int(s[2][0]))
                        ss = [ (msb,lsb) for (msb,lsb,slice) in reversed(ss) ]
                        fields[f] = ss

                    if re.match('^[a-zA-Z_]\w*$', name):
                        # merge any new fields in (mostly to handle external views of regs)
                        if name in regs:
                            for f,ss in regs[name][2].items():
                                if f not in fields:
                                    fields[f] = ss
                            length = max(length, regs[name][1])
                        regs[name] = (long, length, fields, bounds)

    # Read proprietary notice
    notice = ["Proprietary Notice"]
    xml = ET.parse(os.path.join(args.dir[0], 'notice.xml'))
    for p in xml.iter('para'):
        para = ET.tostring(p, method='text').decode().rstrip()
        para = para.replace("&#8217;", '"')
        para = para.replace("&#8220;", '"')
        para = para.replace("&#8221;", '"')
        para = para.replace("&#8482;", '(TM)')
        para = para.replace("&#169;", '(C)')
        para = para.replace("&#174;", '(R)')
        lines = para.split('\n')
        notice.extend(lines)

    regfile = args.output + ".asl"
    accfile = args.output + "_access.asl"

    # Generate file of definitions
    with open(regfile, "w") as f:
        print('/'*72, file=f)
        for p in notice:
            print('// '+p, file=f)
        print('/'*72, file=f)
        print(file=f)
        for name in regs.keys():
            (long, length, fields, bounds) = regs[name]
            fs = ", ".join([ ", ".join([msb+":"+lsb for (msb,lsb) in ss]) +" "+nm
                             for nm, ss in fields.items() ])
            type = "__register "+str(length)+" { "+fs+" }"
            if bounds:
                type = 'array ['+bounds[0]+".."+bounds[1]+'] of '+type
            prefix = "// " if long == 'IMPLEMENTATION DEFINED registers' else ""
            print("//", long, file=f)
            print(prefix+type+' '+name+";", file=f)
            print(file=f)


    # Generate file of accessors
    with open(accfile, "w") as f:
        for (name, _, ps) in sysRegRead:
            print(readDecl(name), file=f)
            for l in ps.split('\n'):
                print('    ' + patchAll(l), file=f)
            print('', file=f)

        for (name, _, ps) in sysRegWrite:
            print(writeDecl(name), file=f)
            for l in ps.split('\n'):
                print('    ' + patchAll(l), file=f)
            print('', file=f)

        print("bits(64) AArch64.SysRegRead(integer op0, integer op1, integer CRn, integer CRm, integer op2)", file=f)
        print('    case op0[0:0]:op1[2:0]:CRn[3:0]:CRm[3:0]:op2[2:0] of', file=f)
        for (name, tests, ps) in sysRegRead:
            op0 = parsePattern(tests['op0'])
            op1 = parsePattern(tests['op1'])
            crn = parsePattern(tests['CRn'])
            crm = parsePattern(tests['CRm'])
            op2 = parsePattern(tests['op2'])
            if op0 and op1 and crn and crm and op2:
                assert(op0[0] == '1')
                print('        when \'' + op0[1] + op1 + crn + crm + op2 + '\' return ' + readCall(name) + ';', file=f)
            else:
                print("Failed to construct pattern for: " + name + " " + str(tests))
        print('        otherwise Unreachable();', file=f)
        print('', file=f)

        print("AArch64.SysRegWrite(integer op0, integer op1, integer CRn, integer CRm, integer op2, bit(64) val)", file=f)
        print('    case op0[0:0]:op1[2:0]:CRn[3:0]:CRm[3:0]:op2[2:0] of', file=f)
        for (name, tests, ps) in sysRegWrite:
            op0 = parsePattern(tests['op0'])
            op1 = parsePattern(tests['op1'])
            crn = parsePattern(tests['CRn'])
            crm = parsePattern(tests['CRm'])
            op2 = parsePattern(tests['op2'])
            if op0 and op1 and crn and crm and op2:
                assert(op0[0] == '1')
                print('        when \'' + op0[1] + op1 + crn + crm + op2 + '\' ' + writeCall(name) + ';', file=f)
            else:
                print("Failed to construct pattern for: " + name + " " + str(tests))
        print('        otherwise Unreachable();', file=f)

    return


if __name__ == "__main__":
    sys.exit(main())
