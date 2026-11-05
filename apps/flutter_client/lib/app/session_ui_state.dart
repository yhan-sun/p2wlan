/// Small presentation preferences for one authenticated shell session.
/// No runtime snapshots, credentials, peers or network authority are retained.
class SessionUiState {
  int? _revision;
  Object? _owner;
  HomeUiState home = HomeUiState();
  DevicesUiState devices = DevicesUiState();

  bool synchronize(int revision, {Object? owner}) {
    if (_revision == revision && identical(_owner, owner)) return false;
    _revision = revision;
    _owner = owner;
    home = HomeUiState();
    devices = DevicesUiState();
    return true;
  }
}

class HomeUiState {
  String? scopeId;
  double scrollOffset = 0;
}

class DevicesUiState {
  String? scopeId;
  String query = '';
  String filter = 'all';
  String sort = 'recommended';
  double scrollOffset = 0;
}
