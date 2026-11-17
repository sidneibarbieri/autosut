import json
import subprocess

import pytest
from pydantic import ValidationError

from scripts.orchestrator.docker_images import (
    DockerImageIdentity, DockerImageLock, inspect_image, resolve_image, verify_images,
)

IMAGE_ID = 'sha256:' + 'a' * 64
REFERENCE = 'example/target:review'


def identity(**changes):
    return DockerImageIdentity(image_id=IMAGE_ID, operating_system='linux', architecture='arm64', **changes)


def test_locked_reference_executes_by_identity(monkeypatch, tmp_path):
    lock = DockerImageLock(images={REFERENCE: identity()})
    path = tmp_path / 'images.json'
    path.write_text(lock.model_dump_json())
    monkeypatch.setenv('AUTOSUT_DOCKER_IMAGE_LOCK', str(path))
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity())
    assert resolve_image(REFERENCE) == IMAGE_ID


@pytest.mark.parametrize('field,value', [('image_id', 'sha256:' + 'b' * 64), ('architecture', 'amd64'), ('operating_system', 'windows')])
def test_divergent_image_is_refused(monkeypatch, field, value):
    actual = identity().model_copy(update={field: value})
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: actual)
    with pytest.raises(ValueError, match='identity mismatch'):
        verify_images(DockerImageLock(images={REFERENCE: identity()}), [REFERENCE])


def test_undeclared_reference_is_refused_before_docker(monkeypatch):
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: pytest.fail('must not inspect undeclared input'))
    with pytest.raises(ValueError, match='not declared'):
        verify_images(DockerImageLock(images={REFERENCE: identity()}), ['unknown:tag'])


def test_absent_image_preserves_docker_failure(monkeypatch):
    def unavailable(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr='No such image')
    monkeypatch.setattr('scripts.orchestrator.docker_images.subprocess.run', unavailable)
    with pytest.raises(subprocess.CalledProcessError, match='non-zero exit'):
        inspect_image(REFERENCE)


def test_inspection_preserves_daemon_identity_and_platform(monkeypatch):
    data = [{'Id': IMAGE_ID, 'Os': 'linux', 'Architecture': 'arm64', 'Variant': 'v8', 'RepoDigests': ['example/target@sha256:' + 'c'*64]}]
    def inspect(command, **options):
        assert command == ['docker', 'image', 'inspect', REFERENCE]
        assert options['check'] and options['timeout'] == 30
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(data))
    monkeypatch.setattr('scripts.orchestrator.docker_images.subprocess.run', inspect)
    result = inspect_image(REFERENCE)
    assert result.image_id == IMAGE_ID and result.variant == 'v8'


def test_review_mode_preserves_declared_reference(monkeypatch):
    monkeypatch.delenv('AUTOSUT_DOCKER_IMAGE_LOCK', raising=False)
    assert resolve_image(REFERENCE) == REFERENCE


def test_lock_rejects_malformed_digest_and_unknown_fields():
    with pytest.raises(ValidationError):
        DockerImageIdentity(image_id='mutable:tag', operating_system='linux', architecture='arm64')
    with pytest.raises(ValidationError):
        DockerImageLock(images={REFERENCE: identity()}, ignored_policy=True)


def test_lock_remains_frozen_when_input_file_changes(monkeypatch, tmp_path):
    from scripts.orchestrator.docker_images import image_lock_scope
    path = tmp_path / 'images.json'
    path.write_text(DockerImageLock(images={REFERENCE: identity()}).model_dump_json())
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity())
    with image_lock_scope(path):
        path.write_text('invalid replacement')
        assert resolve_image(REFERENCE) == IMAGE_ID


def test_platform_override_cannot_change_locked_architecture(monkeypatch):
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity())
    monkeypatch.setenv('AUTOSUT_DOCKER_PLATFORM', 'linux/amd64')
    with pytest.raises(ValueError, match='conflicts with locked image'):
        verify_images(DockerImageLock(images={REFERENCE: identity()}), [REFERENCE])


def test_target_locked_launch_uses_id_without_pull(monkeypatch, tmp_path):
    from scripts.orchestrator.environment import DockerEnvironment
    from scripts.orchestrator.models import SUTProfile
    path = tmp_path / 'images.json'
    path.write_text(DockerImageLock(images={REFERENCE: identity()}).model_dump_json())
    monkeypatch.setenv('AUTOSUT_DOCKER_IMAGE_LOCK', str(path))
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity())
    commands = []
    def launch(command, **options):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='container-id')
    monkeypatch.setattr('scripts.orchestrator.environment.subprocess.run', launch)
    DockerEnvironment.bring_up(SUTProfile(sut_id='test', base_image=REFERENCE), tmp_path)
    assert len(commands) == 1 and commands[0][:3] == ['docker', 'run', '-d']
    assert IMAGE_ID in commands[0] and REFERENCE not in commands[0]


def test_attacker_locked_launch_never_builds(monkeypatch, tmp_path):
    from scripts.orchestrator.attacker import ATTACKER_IMAGE, ensure_attacker_image
    path = tmp_path / 'images.json'
    path.write_text(DockerImageLock(images={ATTACKER_IMAGE: identity()}).model_dump_json())
    monkeypatch.setenv('AUTOSUT_DOCKER_IMAGE_LOCK', str(path))
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity())
    assert ensure_attacker_image() == IMAGE_ID


def test_repository_digest_mismatch_is_refused(monkeypatch):
    expected = identity(repo_digests=('example/target@sha256:' + 'c' * 64,))
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity())
    with pytest.raises(ValueError, match='identity mismatch'):
        verify_images(DockerImageLock(images={REFERENCE: expected}), [REFERENCE])


def test_variant_mismatch_is_refused(monkeypatch):
    monkeypatch.setattr('scripts.orchestrator.docker_images.inspect_image', lambda reference: identity(variant='v7'))
    with pytest.raises(ValueError, match='identity mismatch'):
        verify_images(DockerImageLock(images={REFERENCE: identity(variant='v8')}), [REFERENCE])
