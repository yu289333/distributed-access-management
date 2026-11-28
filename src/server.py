"""Minimal HTTP service in front of the policy pipeline.

    GET  /healthz                              -> {"status": "ok"}
    POST /policies?provider=aws|azure|gcp      -> parse, store, return the root id
    GET  /policies/<id>                        -> load the tree and emit its provider document

The service is intentionally small: it reuses the parser, tree writer, loader,
and emitter modules and adds no new policy logic. Configuration comes from the
environment: ``DATABASE_URL`` (required), ``PORT`` (default 8080), ``HOST``
(default 0.0.0.0).

There is no authentication: bind it to localhost or a private network only.
"""

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import psycopg2

if not __package__:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.conditions.cel import populate_condition_cel
from src.tree import canonicalize
from src.postgres.export import load_policy_tree
from src.postgres.store import write_policy_tree
from src.providers.aws.cel import aws
from src.providers.aws.emitter import emit_policy
from src.providers.aws.parser import parse_policy as parse_aws
from src.providers.azure.cel import azure
from src.providers.azure.emitter import emit_policy as emit_azure
from src.providers.azure.parser import parse_policy as parse_azure
from src.providers.gcp.emitter import emit_policy as emit_gcp
from src.providers.gcp.parser import parse_policy as parse_gcp

PARSERS = {'aws': (parse_aws, aws), 'azure': (parse_azure, azure), 'gcp': (parse_gcp, None)}
MAX_BODY = 1024 * 1024
POLICY_PATH = re.compile(r'^/policies/(\d+)$')


class NotFound(Exception):
    """The requested policy tree does not exist."""


def connect():
    dsn = os.environ.get('DATABASE_URL')
    if not dsn:
        raise RuntimeError('DATABASE_URL is not set')
    return psycopg2.connect(dsn)


def count_nodes(tree):
    return 1 + sum(count_nodes(child) for child in tree.get('children', []))


def _flag(params, name, default=False):
    return params[name][0].lower() in ('1', 'true', 'yes') if name in params else default


class PolicyHandler(BaseHTTPRequestHandler):
    server_version = 'policy-service/0.1'

    def log_message(self, fmt, *args):
        sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))

    def _send(self, status, payload):
        body = json.dumps(payload, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, status, message):
        self._send(status, {'error': message})

    def _read_body(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0:
            raise ValueError('A JSON request body is required')
        if length > MAX_BODY:
            raise ValueError(f'Request body exceeds {MAX_BODY} bytes')
        return self.rfile.read(length)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == '/healthz':
            return self._health()
        match = POLICY_PATH.match(parsed.path)
        if not match:
            return self._fail(404, 'Not found')
        try:
            connection = connect()
            try:
                loaded = load_policy_tree(connection, int(match.group(1)))
            finally:
                connection.close()
            tree = canonicalize(loaded) if _flag(params, 'canonical') else loaded
            payload = {'tree': tree}
            # Emit from the lossless tree, which retains every source rule.
            if loaded.get('provider') == 'AWS':
                payload['document'] = emit_policy(loaded)
            elif loaded.get('provider') == 'Azure':
                payload['document'] = emit_azure(loaded)
            elif loaded.get('provider') == 'GCP':
                payload['document'] = emit_gcp(loaded)
            self._send(200, payload)
        except ValueError as exc:
            if 'not found' in str(exc):
                self._fail(404, str(exc))
            else:
                self._fail(400, str(exc))
        except (psycopg2.Error, RuntimeError) as exc:
            self._log_db_error(exc)
            self._fail(503, 'Database unavailable')

    def do_POST(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path != '/policies':
            return self._fail(404, 'Not found')
        provider = params.get('provider', [''])[0].lower()
        if provider not in PARSERS:
            return self._fail(400, 'provider must be one of: aws, azure, gcp')
        try:
            source = self._read_body().decode('utf-8-sig')
            name = params.get('name', [None])[0]
            parse_policy, translate = PARSERS[provider]
            tree = parse_policy(source, name=name)
            if translate is not None and _flag(params, 'cel', default=True):
                populate_condition_cel(tree, translate=translate)
            counted_tree = canonicalize(tree) if _flag(params, 'canonical') else tree
            connection = connect()
            try:
                # write_policy_tree owns the transaction (it re-enters the
                # connection), so do not wrap it in another `with connection`.
                root_id = write_policy_tree(connection, tree)
            finally:
                connection.close()
            self._send(201, {'id': root_id, 'provider': tree['provider'],
                             'name': tree['name'], 'nodes': count_nodes(counted_tree)})
        except json.JSONDecodeError as exc:
            self._fail(400, f'Invalid JSON: {exc.msg}')
        except ValueError as exc:
            self._fail(400, str(exc))
        except (psycopg2.Error, RuntimeError) as exc:
            self._log_db_error(exc)
            self._fail(503, 'Database unavailable')

    def _health(self):
        try:
            with connect() as connection, connection.cursor() as cursor:
                cursor.execute('SELECT 1')
                cursor.fetchone()
        except (psycopg2.Error, RuntimeError) as exc:
            self._log_db_error(exc)
            return self._fail(503, 'Database unavailable')
        self._send(200, {'status': 'ok'})

    def _log_db_error(self, exc):
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        sys.stderr.write(f'database error: {first}\n')


def create_server(host='0.0.0.0', port=8080):
    return ThreadingHTTPServer((host, port), PolicyHandler)


def main():
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '8080'))
    server = create_server(host, port)
    sys.stderr.write(f'policy-service listening on http://{host}:{port}\n')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
