import logging
from pathlib import Path

import numpy as np
from django.conf import settings

logger = logging.getLogger("modelguard")

ONNX_LIMITATIONS = [
    "ONNX execution uses a hardened CPU-only InferenceSession with external data disabled.",
    "Only standard ONNX domains and a bounded node count are accepted.",
    "Results remain demonstrations on synthetic inputs and do not certify production robustness.",
]

DISALLOWED_OPS = {"If", "Loop", "Scan", "Python", "PyFunc", "Custom", "Trilu"}


class ONNXAdapterError(ValueError):
    pass


class SafeOnnxModel:
    def __init__(self, session, input_name, output_name, feature_names, expected_features):
        self.session = session
        self.input_name = input_name
        self.output_name = output_name
        self.feature_names = feature_names
        self.expected_features = expected_features

    def _prepare(self, X):
        values = np.asarray(X, dtype=np.float32)
        if values.ndim != 2:
            raise ONNXAdapterError("ONNX input data must be a two-dimensional array.")
        if self.expected_features and values.shape[1] != self.expected_features:
            raise ONNXAdapterError(
                f"ONNX model expects {self.expected_features} features, received {values.shape[1]}."
            )
        return np.ascontiguousarray(values)

    def predict_proba(self, X):
        values = self._prepare(X)
        outputs = self.session.run([self.output_name], {self.input_name: values})[0]
        values = np.asarray(outputs, dtype=np.float64)
        if values.ndim == 1:
            values = values.reshape(-1, 1)
        if values.ndim > 2:
            values = values.reshape(values.shape[0], -1)
        if values.shape[0] != len(X):
            raise ONNXAdapterError("ONNX output batch size does not match the input batch size.")
        if values.shape[1] == 1:
            positive = 1.0 / (1.0 + np.exp(-np.clip(values[:, 0], -50, 50)))
            return np.column_stack([1.0 - positive, positive])
        clipped = np.clip(values, 0.0, None)
        totals = clipped.sum(axis=1, keepdims=True)
        safe = np.divide(clipped, totals, out=np.zeros_like(clipped), where=totals > 0)
        return safe

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1).astype(int)


def _input_shape(input_info):
    tensor_type = input_info.type.tensor_type
    shape = tensor_type.shape
    if not shape.dim:
        return None
    dimensions = []
    for dim in shape.dim:
        if dim.HasField("dim_value"):
            dimensions.append(int(dim.dim_value))
        else:
            dimensions.append(None)
    return dimensions


def validate_onnx_file(path, filename=""):
    if not settings.MG_ENABLE_ONNX:
        raise ONNXAdapterError("ONNX execution is disabled.")
    try:
        import onnx
        import onnxruntime as ort
    except ImportError as exc:
        raise ONNXAdapterError(f"ONNX runtime is unavailable: {exc}") from exc

    path = Path(path)
    size = path.stat().st_size
    if size == 0 or size > min(settings.MG_MAX_UPLOAD_BYTES, 100 * 1024 * 1024):
        raise ONNXAdapterError("ONNX model size is outside the supported range.")
    with path.open("rb") as handle:
        signature = handle.read(2)
        if len(signature) != 2 or signature[0] != 0x08 or not 1 <= signature[1] <= 20:
            raise ONNXAdapterError("ONNX protobuf signature is missing.")

    try:
        model = onnx.load_model(str(path), load_external_data=False)
        onnx.checker.check_model(model, full_check=True)
    except Exception as exc:
        raise ONNXAdapterError(f"ONNX model failed structural validation: {exc}") from exc

    graph = model.graph
    if len(graph.node) > settings.MG_ONNX_MAX_NODES:
        raise ONNXAdapterError("ONNX graph exceeds the configured node limit.")
    initializer_names = {item.name for item in graph.initializer}
    for item in graph.initializer:
        if item.external_data:
            raise ONNXAdapterError("External tensor data is not allowed.")
    for node in graph.node:
        if node.domain not in settings.MG_ONNX_ALLOWED_DOMAINS:
            raise ONNXAdapterError(f"ONNX domain {node.domain!r} is not allowed.")
        if node.op_type in DISALLOWED_OPS:
            raise ONNXAdapterError(f"ONNX operator {node.op_type} is not allowed.")

    float_type = onnx.TensorProto.FLOAT
    candidates = [
        item for item in graph.input
        if item.name not in initializer_names
        and item.type.HasField("tensor_type")
        and item.type.tensor_type.elem_type == float_type
    ]
    if len(candidates) != 1:
        raise ONNXAdapterError("Exactly one float tensor input is required.")
    input_info = candidates[0]
    shape = _input_shape(input_info)
    if not shape or len(shape) != 2:
        raise ONNXAdapterError("ONNX input must be a rank-two [batch, features] tensor.")
    feature_dim = shape[1]
    if feature_dim is None or not 2 <= feature_dim <= 64:
        raise ONNXAdapterError("ONNX feature dimension must be fixed between 2 and 64.")

    outputs = [item for item in graph.output if item.type.HasField("tensor_type")]
    if len(outputs) != 1:
        raise ONNXAdapterError("Exactly one tensor output is required.")
    output_name = outputs[0].name

    options = ort.SessionOptions()
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
    options.enable_mem_pattern = False
    options.log_severity_level = 3
    try:
        session = ort.InferenceSession(
            model.SerializeToString(),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
    except Exception as exc:
        raise ONNXAdapterError(f"ONNX InferenceSession could not be created: {exc}") from exc

    feature_names = [f"onnx_feature_{index + 1}" for index in range(feature_dim)]
    adapter = SafeOnnxModel(session, input_info.name, output_name, feature_names, feature_dim)
    logger.info("Validated ONNX model %s with %s features", filename or path.name, feature_dim)
    return adapter, feature_names
