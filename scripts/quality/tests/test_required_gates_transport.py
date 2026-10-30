import contextlib
import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_required_gates as gates

SHA = 'a' * 40


def run(conclusion='success'):
    return gates.WorkflowRun(run_id=1, workflow_name='CI', event='pull_request', head_sha=SHA,
        status='completed', conclusion=conclusion, run_attempt=1, created_at='2026-10-25T00:00:00Z',
        jobs=(gates.JobResult(name='CI Required', status='completed', conclusion=conclusion),))


class GateTransportControls(unittest.TestCase):
    def query_error(self, errors):
        client = gates.GitHubClient('owner/repo', 'fixture-secret', retries=3)
        with patch.object(gates.urllib.request, 'urlopen', side_effect=errors) as query, patch.object(gates.time, 'sleep'):
            try:
                client._paginate('/fixture', 'workflow_runs', {})
            except gates.GateRequestError as error:
                self.assertEqual(query.call_count, 3)
                return error
        self.fail('transport failure cannot produce metadata success')

    def http(self, status):
        return urllib.error.HTTPError('https://api.github.com/fixture', status, 'fixture', {}, None)

    def cli(self, outcomes, *, expired=False):
        client = Mock(); client.runs_for.side_effect = outcomes
        clock = [100.0, 102.0] if expired else None
        with patch.object(gates, '_client', return_value=client), patch.object(gates.time, 'monotonic',
                side_effect=clock, return_value=100.0), patch.object(gates.time, 'sleep') as sleep, \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            result = gates.main(['--sha', SHA, '--require', 'CI Required', '--timeout-seconds', '1'])
        return result, client, sleep, out.getvalue(), err.getvalue()

    def test_exhausted_three_HTTP502_reads_remain_error_and_allow_only_bounded_fresh_metadata_wait(self):
        error = self.query_error([self.http(502) for _ in range(3)])
        self.assertIsInstance(error, gates.GateTransientRequestError)
        self.assertIsInstance(error, gates.GateRequestError)

    def test_authentication_error_is_permanent_even_if_later_errors_are_502(self):
        error = self.query_error([self.http(403), self.http(502), self.http(502)])
        self.assertNotIsInstance(error, gates.GateTransientRequestError)
        result, client, sleep, _, _ = self.cli([error])
        self.assertEqual(result, 1); self.assertEqual(client.runs_for.call_count, 1); sleep.assert_not_called()

    def test_malformed_JSON_is_not_reclassified_as_network_pending(self):
        error = self.query_error([io.BytesIO(b'{invalid') for _ in range(3)])
        self.assertNotIsInstance(error, gates.GateTransientRequestError)

    def test_timeout_is_typed_as_temporary_transport_failure(self):
        error = self.query_error([urllib.error.URLError(TimeoutError('fixture timeout')) for _ in range(3)])
        self.assertIsInstance(error, gates.GateTransientRequestError)

    def test_fresh_complete_same_head_success_required_after_transport_failure(self):
        result, client, sleep, out, _ = self.cli([gates.GateTransientRequestError('fixture'), [run()]])
        self.assertEqual(result, 0); self.assertEqual(client.runs_for.call_count, 2); sleep.assert_called_once_with(20)
        self.assertIn('metadata pending', out); self.assertIn('PASS required gates', out)

    def test_original_deadline_still_fails_closed_with_no_success(self):
        result, client, sleep, _, err = self.cli([gates.GateTransientRequestError('fixture')], expired=True)
        self.assertEqual(result, 1); self.assertEqual(client.runs_for.call_count, 1); sleep.assert_not_called()
        self.assertIn('api_error', err)

    def test_fresh_authoritative_failure_cannot_be_masked_by_prior_transport_error(self):
        result, client, sleep, _, err = self.cli([gates.GateTransientRequestError('fixture'), [run('failure')]])
        self.assertEqual(result, 1); self.assertEqual(client.runs_for.call_count, 2); self.assertIn('FAIL required gates', err)

    def test_partial_final_job_cache_cleared_before_new_snapshot(self):
        client = gates.GitHubClient('owner/repo', 'fixture-secret')
        client._job_cache[(1, 1)] = run().jobs
        with patch.object(client, '_run_metadata_for', return_value=[run()]), \
                patch.object(client, 'jobs', side_effect=gates.GateTransientRequestError('later job failed')):
            with self.assertRaises(gates.GateTransientRequestError):
                client.runs_for(SHA, required_workflows={'CI'})
        self.assertEqual(client._job_cache, {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
