import 'dart:async';

import 'package:flutter/material.dart';

import '../../core/api/wake_api.dart';
import '../../core/models/diagnostics_models.dart';
import '../../core/rooms/room_profiles.dart';
import '../../core/state/settings_store.dart';
import 'wake_strings.dart';

Future<void> showWakeDialog(
  BuildContext context, {
  required SettingsStore settingsStore,
  required WakeStrings strings,
  required WakeTarget target,
}) => showDialog<void>(
  context: context,
  builder: (_) => WakeDialog(
    settingsStore: settingsStore,
    strings: strings,
    target: target,
  ),
);

class WakeDialog extends StatefulWidget {
  const WakeDialog({
    super.key,
    required this.settingsStore,
    required this.strings,
    required this.target,
    this.api,
  });

  final SettingsStore settingsStore;
  final WakeStrings strings;
  final WakeTarget target;
  final WakeApi? api;

  @override
  State<WakeDialog> createState() => _WakeDialogState();
}

class _WakeDialogState extends State<WakeDialog> {
  late final AppSettings _settings;
  late final WakeApi _api;
  WakeStatus? _status;
  WakeJob? _job;
  Timer? _poll;
  Timer? _deadline;
  String? _error;
  String? _jobAgent;
  bool _trackingExisting = false;
  bool _busy = true;
  bool _timedOut = false;
  bool _valid = true;

  WakeStrings get _s => widget.strings;
  bool get _live => mounted && _valid;
  String? get _preferredAgent =>
      widget.settingsStore.wakeAgent(widget.target.id);

  @override
  void initState() {
    super.initState();
    _settings = widget.settingsStore.settings;
    _api =
        widget.api ??
        WakeApi(server: _settings.controlServer, token: _settings.authToken);
    widget.settingsStore.addListener(_settingsChanged);
    unawaited(_load());
  }

  void _settingsChanged() {
    if (!_valid ||
        accountSessionKey(widget.settingsStore.settings) ==
            accountSessionKey(_settings)) {
      return;
    }
    _stopPolling();
    _api.close();
    setState(() {
      _valid = false;
      _busy = false;
      _status = null;
      _job = null;
      _jobAgent = null;
      _error = 'auth_expired';
    });
  }

  @override
  void dispose() {
    widget.settingsStore.removeListener(_settingsChanged);
    _stopPolling();
    if (_valid) _api.close();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _busy = true;
      _error = null;
      _status = null;
      _timedOut = false;
      _job = null;
      _jobAgent = null;
      _trackingExisting = false;
    });
    try {
      final status = await _api.status(widget.target);
      if (_live) setState(() => _status = status);
    } on WakeApiException catch (error) {
      if (_live) setState(() => _error = error.code);
    } finally {
      if (_live) setState(() => _busy = false);
    }
  }

  WakeAgent? get _chosenAgent {
    final agents = _status?.agents ?? const <WakeAgent>[];
    if (agents.length == 1) return agents.single;
    for (final preferred in [_preferredAgent, _status?.preferredAgentId]) {
      for (final agent in agents) {
        if (agent.id == preferred) return agent;
      }
    }
    return null;
  }

  Future<WakeAgent?> _pickAgent(List<WakeAgent> agents) =>
      showDialog<WakeAgent>(
        context: context,
        builder: (dialogContext) => SimpleDialog(
          title: Text(_s.chooseAgent),
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: Text(_s.sameLan),
            ),
            for (final agent in agents)
              SimpleDialogOption(
                onPressed: () => Navigator.pop(dialogContext, agent),
                child: Text(agent.name.isEmpty ? agent.id : agent.name),
              ),
          ],
        ),
      );

  Future<void> _trigger({bool choose = false}) async {
    final status = _status;
    if (!_live ||
        _busy ||
        _deadline != null ||
        status == null ||
        status.availability != WakeAvailability.ready) {
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _job = null;
      _jobAgent = null;
      _trackingExisting = false;
      _timedOut = false;
    });
    try {
      final selected = choose ? null : _chosenAgent;
      final agent = selected ?? await _pickAgent(status.agents);
      if (!_live || agent == null) return;
      final job = await _api.trigger(widget.target, agentId: agent.id);
      if (!_live) return;
      final assigned = job.agentId ?? agent.id;
      final trackedExisting = assigned != agent.id;
      final assignedName = _agentName(status.agents, assigned);
      setState(() {
        _job = job;
        _jobAgent = assignedName;
        _trackingExisting = trackedExisting;
      });
      unawaited(_remember(assigned));
      if (_terminal(job)) return;
      _deadline = Timer(const Duration(seconds: 120), () {
        _stopPolling();
        if (_live) setState(() => _timedOut = true);
      });
      _schedulePoll();
    } on WakeApiException catch (error) {
      if (!_live) return;
      setState(() {
        _error = error.code;
        if (error.code == 'already_online') {
          _status = const WakeStatus(online: true, hasMac: true, agents: []);
        } else if (error.agents case final agents?) {
          _status = WakeStatus(
            online: false,
            hasMac: true,
            agents: agents,
            preferredAgentId: status.preferredAgentId,
          );
        }
      });
    } finally {
      if (_live) setState(() => _busy = false);
    }
  }

  String _agentName(List<WakeAgent> agents, String id) {
    for (final agent in agents) {
      if (agent.id == id && agent.name.isNotEmpty) return agent.name;
    }
    return id;
  }

  Future<void> _remember(String agentId) async {
    try {
      await widget.settingsStore.rememberWakeAgent(widget.target.id, agentId);
    } catch (_) {
      // Saving a preference cannot change the outcome of an accepted task.
    }
  }

  bool _terminal(WakeJob job) =>
      job.state == WakeJobState.failed ||
      job.state == WakeJobState.expired ||
      widget.target.manual && job.state == WakeJobState.sent;

  void _schedulePoll() {
    _poll = Timer(const Duration(seconds: 3), _pollOnce);
  }

  void _stopPolling() {
    _poll?.cancel();
    _deadline?.cancel();
    _deadline = null;
  }

  Future<void> _pollOnce() async {
    final deadline = _deadline;
    final lastJob = _job;
    if (!_live || deadline == null || lastJob == null) return;
    bool active() => _live && identical(_deadline, deadline);
    try {
      if (!widget.target.manual) {
        final status = await _api.status(widget.target);
        if (!active()) return;
        setState(() => _status = status);
        if (status.online) {
          setState(_stopPolling);
          return;
        }
      }
      if (lastJob.state != WakeJobState.sent) {
        final job = await _api.job(lastJob.id);
        if (!active()) return;
        setState(() => _job = job);
        if (_terminal(job)) {
          setState(_stopPolling);
          return;
        }
      }
    } on WakeApiException catch (error) {
      if (!active()) return;
      if (const {
        'auth_expired',
        'wake_not_found',
        'target_blocked',
      }.contains(error.code)) {
        setState(() {
          _stopPolling();
          _error = error.code;
        });
        return;
      }
    }
    if (active()) _schedulePoll();
  }

  @override
  Widget build(BuildContext context) {
    final availability = _status?.availability;
    final canSend =
        _live &&
        !_busy &&
        _deadline == null &&
        !_timedOut &&
        _job == null &&
        widget.target.enabled &&
        availability == WakeAvailability.ready;
    final statusText = switch ((_error, _timedOut, availability, _job, _busy)) {
      (final error?, _, _, _, _) => _s.error(error),
      (_, true, _, _, _) =>
        widget.target.manual ? _s.manualTimedOut : _s.timedOut,
      (_, _, WakeAvailability.online, _, _) => _s.availability(
        WakeAvailability.online,
      ),
      (_, _, _, final job?, _) => _s.job(job, manual: widget.target.manual),
      (_, _, _, _, true) => _status == null ? _s.loading : _s.submitting,
      (_, _, final value?, _, _) =>
        widget.target.enabled ? _s.availability(value) : _s.disabled,
      _ => _s.loading,
    };
    return AlertDialog(
      title: Text(_s.title),
      scrollable: true,
      content: SizedBox(
        width: 360,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            if (_live && widget.target.name.isNotEmpty)
              Text(
                widget.target.name,
                style: Theme.of(context).textTheme.titleSmall,
              ),
            const SizedBox(height: 8),
            Semantics(liveRegion: true, child: Text(statusText)),
            if (_jobAgent case final agent?)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(_s.assignedAgent(agent)),
              ),
            if (_live && _trackingExisting)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(_s.existingJob),
              ),
            if (canSend) ...[
              const SizedBox(height: 12),
              Text(_s.sameLan),
              if (_chosenAgent case final agent?)
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text(agent.name.isEmpty ? agent.id : agent.name),
                ),
              if ((_status?.agents.length ?? 0) > 1 && _chosenAgent != null)
                TextButton(
                  onPressed: () => _trigger(choose: true),
                  child: Text(_s.chooseAndWake),
                ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(_s.close),
        ),
        if (canSend)
          FilledButton(onPressed: _trigger, child: Text(_s.confirm))
        else if (_live && !_busy && _deadline == null)
          OutlinedButton(onPressed: _load, child: Text(_s.refresh)),
      ],
    );
  }
}
