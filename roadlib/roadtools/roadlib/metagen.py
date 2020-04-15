import xml.etree.ElementTree as ET
import sys
tree = ET.parse(sys.argv[1])
root = tree.getroot()

def trl_prop(prop):
    if 'Collection(' in prop:
        return 'Collection'
    prop = prop.replace('Microsoft.DirectoryServices.','')
    return prop

allprops = []

etout = []

ethdr = '''from roadtools.roadlib.metadef.basetypes import Edm, Collection
from roadtools.roadlib.metadef.complextypes import *
'''
etout.append(ethdr)

ns = {'edm':'http://schemas.microsoft.com/ado/2009/11/edm'}
for entitytype in root.iter('{http://schemas.microsoft.com/ado/2009/11/edm}EntityType'): # root.findall('edm:EntityType', ns):
    etname = entitytype.get('Name')
    basetype = entitytype.get('BaseType')
    if basetype:
        basetype = basetype.replace('Microsoft.DirectoryServices.','')
    else:
        basetype = 'object'
    out = '''
class %s(%s):
    props = {
%s
    }
    rels = [
%s
    ]

'''
    props = []

    for prop in entitytype.iter('{http://schemas.microsoft.com/ado/2009/11/edm}Property'):
        props.append("        '%s': %s," % (prop.get('Name'), trl_prop(prop.get('Type'))))
        allprops.append(trl_prop(prop.get('Type')))

    rels = []
    for relout in entitytype.iter('{http://schemas.microsoft.com/ado/2009/11/edm}NavigationProperty'):
        rels.append("        '%s'," % (relout.get('Name')))

    etout.append(out % (etname, basetype, '\n'.join(props), '\n'.join(rels)))

# Simple classes, no references
ctsout = []
# Complex classes, possibly references
ctcout = []
cthdr = '''from roadtools.roadlib.metadef.basetypes import Edm, Collection
'''
ctsout.append(cthdr)

for entitytype in root.iter('{http://schemas.microsoft.com/ado/2009/11/edm}ComplexType'): # root.findall('edm:EntityType', ns):
    ctname = entitytype.get('Name')
    basetype = 'object'
    out = '''
class %s(%s):
    props = {
%s
    }

'''
    props = []
    hascomplex = False
    for prop in entitytype.iter('{http://schemas.microsoft.com/ado/2009/11/edm}Property'):
        # Possibly complex type, these should come last
        if prop.get('Type') and 'Microsoft.DirectoryServices' in prop.get('Type'):
            hascomplex = True
        props.append("        '%s': %s," % (prop.get('Name'), trl_prop(prop.get('Type'))))
        allprops.append(trl_prop(prop.get('Type')))

    if hascomplex:
        # print('Complex')
        ctcout.append(out % (ctname, basetype, '\n'.join(props)))
    else:
        ctsout.append(out % (ctname, basetype, '\n'.join(props)))

with open('metadef/entitytypes.py', 'w') as fout:
    fout.write(''.join(etout))

with open('metadef/complextypes.py', 'w') as fout:
    fout.write(''.join(ctsout))
    fout.write(''.join(ctcout))


# raprops = set(allprops)
# print raprops
