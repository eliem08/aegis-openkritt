from __future__ import annotations

import json
import struct
import zipfile

import pytest

from aegis.ai.jarvis.model_provenance import (
    ModelProvenanceError,
    inspect_model_provenance,
    issue_model_artifact_ticket,
)


def _inspect(path, scope="scope:model"):
    ticket = issue_model_artifact_ticket(path, scope_digest=scope)
    return inspect_model_provenance(path, ticket=ticket, scope_digest=scope)


def test_safetensors_header_is_parsed_without_reading_metadata_values(tmp_path):
    model = tmp_path / "demo.safetensors"
    header = {
        "__metadata__": {
            "framework": "pt",
            "secret_token": "DO-NOT-LEAK-THIS",
        },
        "weight": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, 16],
        },
    }
    raw = json.dumps(header, separators=(",", ":")).encode()
    model.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 16)
    report = _inspect(model)
    assert report.format == "safetensors"
    assert report.format_confidence == "structural"
    assert set(report.metadata_keys) == {"framework", "secret_token"}
    assert len(report.tensor_headers) == 1
    assert report.tensor_headers[0].name == "weight"
    assert report.tensor_headers[0].dtype == "F32"
    assert report.tensor_headers[0].shape == (2, 2)
    assert report.deserialized is False
    assert "DO-NOT-LEAK-THIS" not in repr(report)


def test_pytorch_zip_is_recognized_from_structure_without_unpickling(tmp_path):
    model = tmp_path / "checkpoint.pt"
    with zipfile.ZipFile(model, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("archive/data.pkl", b"malicious-pickle-bytes-never-loaded")
        bundle.writestr("archive/data/0", b"tensor-bytes")
        bundle.writestr("archive/version", b"3")
        bundle.writestr("archive/byteorder", b"little")
    report = _inspect(model)
    assert report.format == "pytorch_zip_checkpoint"
    assert report.archive_entries == 4
    assert "contains_pickle_metadata" in report.structural_flags
    assert report.deserialized is False
    assert "malicious-pickle-bytes-never-loaded" not in repr(report)


def test_keras_v3_zip_is_recognized_by_container_entries_only(tmp_path):
    model = tmp_path / "demo.keras"
    with zipfile.ZipFile(model, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("config.json", '{"class_name":"Functional"}')
        bundle.writestr("metadata.json", '{"keras_version":"3"}')
        bundle.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\nweights")
    report = _inspect(model)
    assert report.format == "keras_v3_zip"
    assert "keras_config_metadata_weights" in report.structural_flags
    assert report.archive_names == ("config.json", "metadata.json", "model.weights.h5")
    assert report.deserialized is False


def test_hdf5_pickle_gguf_and_onnx_are_format_observations_not_findings(tmp_path):
    h5 = tmp_path / "model.h5"
    h5.write_bytes(b"\x89HDF\r\n\x1a\n" + b"x" * 64)
    assert _inspect(h5).format == "hdf5"

    pkl = tmp_path / "model.pkl"
    pkl.write_bytes(b"\x80\x04" + b"not-loaded")
    pkl_report = _inspect(pkl)
    assert pkl_report.format == "pickle_protocol"
    assert "pickle_like_not_loaded" in pkl_report.structural_flags

    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(b"GGUF" + b"\x00" * 64)
    assert _inspect(gguf).format == "gguf"

    onnx = tmp_path / "model.onnx"
    onnx.write_bytes(b"protobuf-ish")
    onnx_report = _inspect(onnx)
    assert onnx_report.format == "onnx_protobuf"
    assert onnx_report.format_confidence == "extension"
    assert onnx_report.deserialized is False


def test_malformed_safetensors_offsets_fail_closed(tmp_path):
    model = tmp_path / "bad.safetensors"
    header = {
        "weight": {
            "dtype": "F32",
            "shape": [2],
            "data_offsets": [0, 999999],
        }
    }
    raw = json.dumps(header).encode()
    model.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 8)
    with pytest.raises(ModelProvenanceError, match="offsets exceed"):
        _inspect(model)


def test_archive_bomb_ratio_and_entry_count_fail_closed(tmp_path):
    model = tmp_path / "bomb.pt"
    with zipfile.ZipFile(model, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("archive/data.pkl", b"A" * 200_000)
        bundle.writestr("archive/version", b"3")
    ticket = issue_model_artifact_ticket(model, scope_digest="scope:model")
    with pytest.raises(ModelProvenanceError, match="compression-ratio"):
        inspect_model_provenance(
            model,
            ticket=ticket,
            scope_digest="scope:model",
            max_compression_ratio=2.0,
        )

    many = tmp_path / "many.pt"
    with zipfile.ZipFile(many, "w", compression=zipfile.ZIP_STORED) as bundle:
        for index in range(5):
            bundle.writestr(f"archive/data/{index}", b"x")
    ticket = issue_model_artifact_ticket(many, scope_digest="scope:model")
    with pytest.raises(ModelProvenanceError, match="entry-count"):
        inspect_model_provenance(
            many,
            ticket=ticket,
            scope_digest="scope:model",
            max_archive_entries=2,
        )


def test_ticket_binds_scope_name_size_and_full_artifact_digest(tmp_path):
    model = tmp_path / "demo.pkl"
    model.write_bytes(b"\x80\x04payload")
    ticket = issue_model_artifact_ticket(model, scope_digest="scope:one")
    with pytest.raises(ModelProvenanceError, match="scope digest mismatch"):
        inspect_model_provenance(model, ticket=ticket, scope_digest="scope:two")
    model.write_bytes(model.read_bytes() + b"tamper")
    with pytest.raises(ModelProvenanceError, match="changed after ticket"):
        inspect_model_provenance(model, ticket=ticket, scope_digest="scope:one")
