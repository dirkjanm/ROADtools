import xml.etree.ElementTree as ET
import sys
tree = ET.parse(sys.argv[1])
root = tree.getroot()

def trl_prop(prop, curnamespace=''):
    if 'Collection(' in prop:
        return 'Collection'
    # prop = prop.replace('windowsUpdates.','').replace('search.','').replace('microsoft.graph.ediscovery.','').replace('microsoft.graph.','').replace('graph.','').replace('identityGovernance.','identityGovernance_').replace('networkaccess.','networkaccess_')
    prop = prop.replace('.','_').replace('microsoft_graph_','').replace('graph_','').replace('Edm_','Edm.').replace('self_', curnamespace)
    if not 'Edm' in prop and '_' in prop:
        return 'Collection, #extnamespace: {0}'.format(prop)
    return prop

allprops = []

etout = []

ethdr = '''from roadtools.roadlib.metadef.basetypes import Edm, Collection
from roadtools.roadlib.metadef.complextypes_msgraph import *
class entity(object):
    props = {
        'id': Edm.String,
    }
    rels = [

    ]


class directoryObject(entity):
    props = {
        'deletedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]
'''
etout.append(ethdr)
etout_simple = []
etout_complex = []

ns = {'edm':'http://schemas.microsoft.com/ado/2009/11/edm'}
for namespace in root.iter('{http://docs.oasis-open.org/odata/ns/edm}Schema'): # root.findall('edm:EntityType', ns):
    basename = namespace.get('Namespace').replace('microsoft.graph.','').replace('graph.','')
    if basename != 'microsoft.graph':
        prefix = basename.replace('.','_') + '_'
    else:
        prefix = ''
    for entitytype in namespace.iter('{http://docs.oasis-open.org/odata/ns/edm}EntityType'): # root.findall('edm:EntityType', ns):
        etname = prefix + entitytype.get('Name')
        if etname == 'print':
            continue
        basetype = entitytype.get('BaseType')
        # remove group from termstore set which has entity as basetype instead of the directory group which has directoryobject as basetype
        if etname == 'group' and basetype == 'graph.entity':
            continue
        if etname in ('entity', 'directoryObject'):
            continue
        if basetype:
            # basetype = basetype.replace('windowsUpdates.','').replace('search.','').replace('microsoft.graph.ediscovery.','').replace('microsoft.graph.','').replace('graph.','').replace('identityGovernance.','identityGovernance_').replace('networkaccess.','networkaccess_')
            basetype = basetype.replace('.','_').replace('microsoft_graph_','').replace('graph_','').replace('self_', prefix)
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

        for prop in entitytype.iter('{http://docs.oasis-open.org/odata/ns/edm}Property'):
            props.append("        '%s': %s," % (prop.get('Name'), trl_prop(prop.get('Type'), prefix)))
            allprops.append(trl_prop(prop.get('Type')))

        rels = []
        for relout in entitytype.iter('{http://docs.oasis-open.org/odata/ns/edm}NavigationProperty'):
            rels.append("        '%s'," % (relout.get('Name')))
        if basetype in ('object', 'entity', 'directoryObject'):
            etout_simple.append(out % (etname, basetype, '\n'.join(props), '\n'.join(rels)))
        else:
            etout_complex.append(out % (etname, basetype, '\n'.join(props), '\n'.join(rels)))


# Simple classes, no references
ctsout = []
# Complex classes, possibly references
ctcout = []
# All classes, to resolve references
allclass = []

cthdr = '''from roadtools.roadlib.metadef.basetypes import Edm, Collection
import enum
'''
ctsout.append(cthdr)

for namespace in root.iter('{http://docs.oasis-open.org/odata/ns/edm}Schema'): # root.findall('edm:EntityType', ns):
    basename = namespace.get('Namespace').replace('microsoft.graph.','').replace('graph.','')
    if basename != 'microsoft.graph':
        prefix = basename.replace('.','_') + '_'
    else:
        prefix = ''
    for entitytype in namespace.iter('{http://docs.oasis-open.org/odata/ns/edm}EnumType'): # root.findall('edm:EntityType', ns):
        ctname = prefix + entitytype.get('Name')
        out = '''
{entname}_data = {{
{entdict}
}}
{entname} = enum.Enum('{entname}', {entname}_data)

'''
        values = []
        for prop in entitytype.iter('{http://docs.oasis-open.org/odata/ns/edm}Member'):
            # Possibly complex type, these should come last
            values.append("    '%s': %s," % (prop.get('Name'), trl_prop(prop.get('Value'))))

        # Do these first
        ctsout.append(out.format(entname=ctname, entdict='\n'.join(values)))
        allclass.append(ctname)

re_iter = []
out = '''
class %s(%s):
    props = {
%s
    }

'''
for namespace in root.iter('{http://docs.oasis-open.org/odata/ns/edm}Schema'): # root.findall('edm:EntityType', ns):
    basename = namespace.get('Namespace').replace('microsoft.graph.','').replace('graph.','')
    if basename != 'microsoft.graph':
        prefix = basename.replace('.','_') + '_'
    else:
        prefix = ''
    for entitytype in namespace.iter('{http://docs.oasis-open.org/odata/ns/edm}ComplexType'): # root.findall('edm:EntityType', ns):
        ctname = prefix + entitytype.get('Name')
        basetype = 'object'
        props = []
        proptypes = []
        hascomplex = False
        for prop in entitytype.iter('{http://docs.oasis-open.org/odata/ns/edm}Property'):
            # Yet undefined complex type, keep for later to see if the problem fixes itself
            translated = trl_prop(prop.get('Type'))
            if not translated in allclass and not translated.startswith('Collection') and not 'Edm.' in translated:
                if 'cloudPc' in translated:
                    print(ctname, translated)
                hascomplex = True
            props.append("        '%s': %s," % (prop.get('Name'), translated))
            proptypes.append(translated)
            allprops.append(translated)
        if hascomplex:
            re_iter.append((ctname, basetype, props, proptypes))
        else:
            ctsout.append(out % (ctname, basetype, '\n'.join(props)))
            allclass.append(ctname)

# Try to filter out the ones resolved now
for i in range(10):
    for item in re_iter.copy():
        ctname, basetype, props, proptypes = item
        unref = False
        for translated in proptypes:
            if not translated in allclass and not translated.startswith('Collection') and not 'Edm.' in translated:
                unref = True
        if not unref:
            print('Resolved', ctname)
            ctsout.append(out % (ctname, basetype, '\n'.join(props)))
            allclass.append(ctname)
            re_iter.remove(item)

# Final chunks, init later because they self-reference or circle reference
out = '''
class %s(%s):
    props = {}
    def __init__(self):
        self.__class__.props = {
    %s
        }

'''
for item in re_iter:
    ctname, basetype, props, proptypes = item
    ctcout.append(out % (ctname, basetype, '\n    '.join(props)))

with open('metadef/entitytypes_msgraph.py', 'w') as fout:
    fout.write(''.join(etout))
    fout.write(''.join(etout_simple))
    fout.write(''.join(etout_complex))

with open('metadef/complextypes_msgraph.py', 'w') as fout:
    fout.write(''.join(ctsout))
    fout.write('# Self-referential and circle reference types')
    fout.write(''.join(ctcout))


# raprops = set(allprops)
# print raprops
