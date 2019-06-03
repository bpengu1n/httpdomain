"""
    sphinxcontrib.autohttp.flask
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    The sphinx.ext.autodoc-style SocketIO API reference builder (from Flask_SocketIO)
    for sphinxcontrib.httpdomain.

    :copyright: Copyright 2019 by BPengu1n
    :license: BSD, see LICENSE for details.

"""

import re
import itertools
import six
import collections

from docutils.parsers.rst import directives, Directive

from sphinx.util import force_decode
from sphinx.util.docstrings import prepare_docstring
from sphinx.pycode import ModuleAnalyzer

from sphinxcontrib.autohttp.common import sio_directive, import_object


def translate_werkzeug_rule(rule):
    from werkzeug.routing import parse_rule
    buf = six.StringIO()
    for conv, arg, var in parse_rule(rule):
        if conv:
            buf.write('(')
            if conv != 'default':
                buf.write(conv)
                buf.write(':')
            buf.write(var)
            buf.write(')')
        else:
            buf.write(var)
    return buf.getvalue()


def get_routes(app, endpoint=None, order=None):
    endpoints = []
    for h_msg, h_handler, h_ns in app.handlers:
        yield h_handler, h_ns, h_msg


def get_blueprint(app, view_func):
    for name, func in app.view_functions.items():
        if view_func is func:
            return name.split('.')[0]


def cleanup_methods(methods):
    autoadded_methods = frozenset(['OPTIONS', 'HEAD'])
    if methods <= autoadded_methods:
        return methods
    return methods.difference(autoadded_methods)


def quickref_directive(method, path, content, blueprint=None, auto=False):
    rcomp = re.compile("^\s*.. :quickref:\s*(?P<quick>.*)$")
    method = method.lower().strip()
    if isinstance(content, six.string_types):
        content = content.splitlines()
    description = ""
    name = ""
    ref = path.replace("<", "(").replace(">", ")") \
              .replace("/", "-").replace(":", "-")
    for line in content:
        qref = rcomp.match(line)
        if qref:
            quickref = qref.group("quick")
            parts = quickref.split(";", 1)
            if len(parts) > 1:
                name = parts[0]
                description = parts[1]
            else:
                description = quickref
            break

    if auto:
        if not description and content:
            description = content[0]
        if not name and blueprint:
            name = blueprint

    row = {}
    row['name'] = name
    row['operation'] = '      - `%s %s <#%s-%s>`_' % (
        method.upper(), path, method.lower(), ref)
    row['description'] = description

    return row


class AutoflaskBase(Directive):
    has_content = True
    required_arguments = 1
    option_spec = {'endpoints': directives.unchanged,
                   'order': directives.unchanged,
                   'groupby': directives.unchanged,
                   'undoc-endpoints': directives.unchanged,
                   'undoc-static': directives.unchanged,
                   'include-empty-docstring': directives.unchanged,
                   'autoquickref': directives.flag}

    @property
    def endpoints(self):
        endpoints = self.options.get('endpoints', None)
        if not endpoints:
            return None
        return re.split(r'\s*,\s*', endpoints)

    @property
    def undoc_endpoints(self):
        undoc_endpoints = self.options.get('undoc-endpoints', None)
        if not undoc_endpoints:
            return frozenset()
        return frozenset(re.split(r'\s*,\s*', undoc_endpoints))

    @property
    def order(self):
        order = self.options.get('order', None)
        if order not in (None, 'path'):
            raise ValueError('Invalid value for :order:')
        return order

    @property
    def groupby(self):
        groupby = self.options.get('groupby', None)
        if not groupby:
            return frozenset()
        return frozenset(re.split(r'\s*,\s*', groupby))

    def inspect_routes(self, app):
        """Inspects the views of Flask.

        :param app: The Flask application.
        :returns: 4-tuple like ``(method, paths, view_func, view_doc)``
        """
        if self.endpoints:
            routes = itertools.chain(*[get_routes(app, endpoint, self.order)
                                       for endpoint in self.endpoints])
        else:
            routes = get_routes(app, order=self.order)

        for method, endpoint in routes:
            if endpoint in self.undoc_endpoints:
                continue

            view = endpoint
            view_func = view.__name__

            view_doc = view.__doc__ or ''

            if not isinstance(view_doc, six.text_type):
                analyzer = ModuleAnalyzer.for_module(view.__module__)
                view_doc = force_decode(view_doc, analyzer.encoding)

            if not view_doc and 'include-empty-docstring' not in self.options:
                continue

            yield (method, view_func, view_doc)

    def groupby_view(self, routes):
        view_to_paths = collections.OrderedDict()
        for method, paths, view_func, view_doc in routes:
            view_to_paths.setdefault(
                (method, view_func, view_doc), []).extend(paths)
        for (method, view_func, view_doc), paths in view_to_paths.items():
            yield (method, paths, view_func, view_doc)

    def make_rst(self, qref=False):
        app = import_object(self.arguments[0])
        routes = self.inspect_routes(app)
        if 'view' in self.groupby:
            routes = self.groupby_view(routes)
        for method, view_func, view_doc in routes:
            docstring = prepare_docstring(view_doc)
            if qref:
                auto = self.options.get("autoquickref", False) is None
                row = quickref_directive(method, view_func, docstring,
                                             None, auto=auto)
                yield row
            else:
                for line in sio_directive('emit', method, docstring):
                    yield line
