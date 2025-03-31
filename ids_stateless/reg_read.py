from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

SWITCH_NAME = 's1'

topo = load_topo('topology.json')
thrift_port = topo.get_thrift_port(SWITCH_NAME)
controller = SimpleSwitchThriftAPI(thrift_port)


results = controller.register_read('IDS_Ingress.counters')
for reg_idx, reg_val in enumerate(results):
    if reg_val > 0:
        print('%d: %d' % (reg_idx, reg_val))
