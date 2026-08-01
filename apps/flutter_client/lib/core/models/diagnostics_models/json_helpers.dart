part of '../diagnostics_models.dart';

String _string(dynamic value, [String fallback = '']) {
  if (value == null) return fallback;
  return value.toString();
}

String? _nullableString(dynamic value) {
  if (value == null) return null;
  final text = value.toString();
  return text.isEmpty ? null : text;
}

int _int(dynamic value, [int fallback = 0]) {
  return _intOrNull(value) ?? fallback;
}

int? _intOrNull(dynamic value) {
  if (value is int) return value;
  if (value is num) return value.round();
  if (value is String) return int.tryParse(value);
  return null;
}

bool _bool(dynamic value, [bool fallback = false]) {
  if (value is bool) return value;
  if (value is String) return value.toLowerCase() == 'true';
  if (value is num) return value != 0;
  return fallback;
}

JsonMap _map(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return {};
}

JsonMap? _mapOrNull(dynamic value) {
  if (value is Map) return Map<String, dynamic>.from(value);
  return null;
}

List<dynamic> _list(dynamic value) {
  if (value is List) return value;
  return const [];
}

List<String> _stringList(dynamic value) {
  return _list(value).map((item) => item.toString()).toList(growable: false);
}
