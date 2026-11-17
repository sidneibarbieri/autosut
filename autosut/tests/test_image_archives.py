import hashlib
import io
import json
import shutil
import tarfile

import pytest

from scripts.orchestrator.docker_images import DockerImageIdentity, DockerImageLock
from scripts.orchestrator.image_archives import archive_sha256, canonical_reference, export_images, name_archive

PAYLOAD = b'{"schemaVersion":2}'
IMAGE_ID = 'sha256:' + hashlib.sha256(PAYLOAD).hexdigest()
REFERENCE = 'python@' + IMAGE_ID


def make_archive(path, blob=PAYLOAD):
    index = {'schemaVersion': 2, 'manifests': [{'digest': IMAGE_ID, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'size': len(PAYLOAD)}]}
    with tarfile.open(path, 'w') as archive:
        for name, data in [('index.json', json.dumps(index).encode()), ('blobs/sha256/' + IMAGE_ID[7:], blob)]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


@pytest.mark.parametrize('reference,expected', [
    ('python:3.11', 'docker.io/library/python:3.11'),
    (REFERENCE, 'docker.io/library/' + REFERENCE),
    ('autosut/attacker:one', 'docker.io/autosut/attacker:one'),
    ('localhost:5000/team/image:one', 'localhost:5000/team/image:one'),
    ('registry.example/team/image:one', 'registry.example/team/image:one'),
])
def test_archive_name_normalization(reference, expected):
    assert canonical_reference(reference) == expected


def test_digest_reference_is_retained_without_altering_blob(tmp_path):
    source, output = tmp_path/'raw.tar', tmp_path/'named.tar'
    make_archive(source)
    original = source.read_bytes()
    name_archive(source, output, {REFERENCE: IMAGE_ID})
    with tarfile.open(output) as archive:
        index = json.load(archive.extractfile('index.json'))
        descriptor = index['manifests'][0]
        assert descriptor['annotations']['io.containerd.image.name'] == 'docker.io/library/' + REFERENCE
        assert descriptor['digest'] == IMAGE_ID
        assert archive.extractfile('blobs/sha256/' + IMAGE_ID[7:]).read() == PAYLOAD
    assert source.read_bytes() == original


def test_multiple_aliases_keep_the_same_descriptor_identity(tmp_path):
    source, output = tmp_path/'raw.tar', tmp_path/'named.tar'
    make_archive(source)
    name_archive(source, output, {REFERENCE: IMAGE_ID, 'team/example:review': IMAGE_ID})
    with tarfile.open(output) as archive:
        descriptors = json.load(archive.extractfile('index.json'))['manifests']
    assert len(descriptors) == 2
    assert {descriptor['digest'] for descriptor in descriptors} == {IMAGE_ID}
    assert len({descriptor['annotations']['io.containerd.image.name'] for descriptor in descriptors}) == 2


@pytest.mark.parametrize('corrupt_blob,locked_id,error', [
    (b'corrupt', IMAGE_ID, 'content mismatch'),
    (PAYLOAD, 'sha256:' + 'b'*64, 'does not preserve'),
])
def test_corrupt_or_unsupported_archive_is_rejected(tmp_path, corrupt_blob, locked_id, error):
    source, output = tmp_path/'raw.tar', tmp_path/'named.tar'
    make_archive(source, corrupt_blob)
    with pytest.raises(ValueError, match=error):
        name_archive(source, output, {REFERENCE: locked_id})
    assert not output.exists()


def test_export_saves_verified_ids_and_refuses_overwrite(monkeypatch, tmp_path):
    fixture, output = tmp_path/'fixture.tar', tmp_path/'export.tar'
    make_archive(fixture)
    identity = DockerImageIdentity(image_id=IMAGE_ID, operating_system='linux', architecture='arm64')
    lock = DockerImageLock(images={REFERENCE: identity})
    calls = []
    monkeypatch.setattr('scripts.orchestrator.image_archives.verify_images', lambda *_: {REFERENCE: identity})
    def save(arguments, **options):
        calls.append(arguments)
        shutil.copyfile(fixture, arguments[4])
    monkeypatch.setattr('scripts.orchestrator.image_archives.subprocess.run', save)
    digest = export_images(lock, [REFERENCE], output)
    assert calls[0][-1] == IMAGE_ID
    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        export_images(lock, [REFERENCE], output)
    assert len(calls) == 1
    assert not list(tmp_path.glob('.autosut-images-*'))


def test_identity_change_during_export_does_not_publish_partial_archive(monkeypatch, tmp_path):
    fixture, output = tmp_path/'fixture.tar', tmp_path/'export.tar'
    make_archive(fixture)
    identity = DockerImageIdentity(image_id=IMAGE_ID, operating_system='linux', architecture='arm64')
    lock = DockerImageLock(images={REFERENCE: identity})
    checks = []
    def verify(*arguments):
        checks.append(arguments)
        if len(checks) == 2:
            raise ValueError('identity mismatch during export')
        return {REFERENCE: identity}
    monkeypatch.setattr('scripts.orchestrator.image_archives.verify_images', verify)
    monkeypatch.setattr('scripts.orchestrator.image_archives.subprocess.run', lambda arguments, **_: shutil.copyfile(fixture, arguments[4]))
    with pytest.raises(ValueError, match='identity mismatch'):
        export_images(lock, [REFERENCE], output)
    assert not output.exists()
    assert not list(tmp_path.glob('.autosut-images-*'))


def test_export_preserves_original_repository_digest_alias(monkeypatch, tmp_path):
    fixture, output = tmp_path/'fixture.tar', tmp_path/'export.tar'
    make_archive(fixture)
    origin = 'registry.example/original@' + IMAGE_ID
    identity = DockerImageIdentity(image_id=IMAGE_ID, operating_system='linux', architecture='arm64', repo_digests=(origin,))
    lock = DockerImageLock(images={REFERENCE: identity})
    monkeypatch.setattr('scripts.orchestrator.image_archives.verify_images', lambda *_: {REFERENCE: identity})
    monkeypatch.setattr('scripts.orchestrator.image_archives.subprocess.run', lambda arguments, **_: shutil.copyfile(fixture, arguments[4]))
    export_images(lock, [REFERENCE], output)
    with tarfile.open(output) as archive:
        names={item['annotations']['io.containerd.image.name'] for item in json.load(archive.extractfile('index.json'))['manifests']}
    assert origin in names
    assert 'docker.io/library/' + REFERENCE in names


def test_export_refuses_repository_digest_outside_its_oci_root(monkeypatch, tmp_path):
    identity = DockerImageIdentity(image_id=IMAGE_ID, operating_system='linux', architecture='arm64', repo_digests=('example/image@sha256:'+'b'*64,))
    lock = DockerImageLock(images={REFERENCE: identity})
    monkeypatch.setattr('scripts.orchestrator.image_archives.verify_images', lambda *_: {REFERENCE: identity})
    monkeypatch.setattr('scripts.orchestrator.image_archives.subprocess.run', lambda *_args, **_kwargs: pytest.fail('must refuse before saving'))
    with pytest.raises(ValueError, match='does not name the exported OCI root'):
        export_images(lock, [REFERENCE], tmp_path/'export.tar')


@pytest.mark.parametrize('payload', [b'', b'archive-boundary' * 100000])
def test_streaming_archive_hash_matches_reference(tmp_path, payload):
    path = tmp_path / 'image.tar'
    path.write_bytes(payload)
    assert archive_sha256(path) == hashlib.sha256(payload).hexdigest()
