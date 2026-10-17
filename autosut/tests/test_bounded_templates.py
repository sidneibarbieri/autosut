import pytest
from planning.bounded_templates import observe_file

class Host:
    def run_shell(self, command, **kwargs):
        from types import SimpleNamespace
        return SimpleNamespace(exit_code=0, stdout='wrong', stderr='')

def test_observer_refuses_tampered_fixture():
    with pytest.raises(ValueError, match='observer mismatch'):
        observe_file(Host(), '/tmp/fixture', 'expected', 'observer.log')
