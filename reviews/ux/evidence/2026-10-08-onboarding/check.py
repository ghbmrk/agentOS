import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
r = json.loads((root/'results.json').read_text())
assert r['host_retry']['requested_trust'] is False
assert r['host_retry']['not_mine_checked'] is False
assert r['host_retry']['retry_with_rendered_defaults_trust'] is True
assert r['private_retry']['calls'] == [False, True]
assert r['private_retry']['private_checked_after_optout'] is True
assert r['private_retry']['key_echoed'] is False
assert r['number_fallback']['code_form'] is True
assert r['number_fallback']['details_open'] is False
assert r['context_change']['elsewhere'] is True
assert r['context_change']['reset_secret_required'] is True
assert r['context_change']['resume_action'] is False
assert r['network_retry']['submitted_ssid'] == 'Synthetic Home'
assert r['network_retry']['selected_attribute'] is False
assert r['network_retry']['first_option_neighbor'] is True
print('All source-level flow observations reproduced.')
