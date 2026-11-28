"""Export stored policy rows as a tree, retaining database IDs."""
from copy import deepcopy

from ..policyTree import COLUMNS, validate_tree


def export_policy_tree(connection, root_id):
    """Read a consistent tree in one query; expose parent as parent_id."""
    with connection.cursor() as cursor:
        cursor.execute('''WITH RECURSIVE tree AS (
            SELECT p.*, ARRAY[p.id] AS visited FROM policy p WHERE id=%s
            UNION ALL
            SELECT p.*, t.visited || p.id FROM policy p JOIN tree t ON p.parent=t.id
            WHERE NOT p.id=ANY(t.visited))
            SELECT id, parent, ''' + ', '.join(f'"{column}"' for column in COLUMNS)
                       + ' FROM tree ORDER BY child_position NULLS LAST, id', (root_id,))
        rows = cursor.fetchall()
    if not rows:
        raise ValueError(f'Policy root {root_id} not found')
    nodes = {row[0]: dict(id=row[0], parent_id=row[1],
                         **dict(zip(COLUMNS, row[2:])), children=[]) for row in rows}
    for row in rows:
        if row[0] != root_id:
            nodes[row[1]]['children'].append(nodes[row[0]])
    return nodes[root_id]


def strip_database_ids(tree):
    """Return a copy of a database export without ``id`` and ``parent_id``.

    ``examples/generated/*.json`` are exports of stored trees: every node also
    carries the row's primary key and its parent's key. Those fields are not part
    of the tree schema, so an export must be stripped before it can be
    validated, compared with parser output, or re-imported.
    """
    node = {key: deepcopy(value) for key, value in tree.items()
            if key not in ('id', 'parent_id')}
    node['children'] = [strip_database_ids(child)
                        for child in tree.get('children', [])]
    return node


def load_policy_tree(connection, root_id):
    """Read one policy tree back as a validated tree without database ids."""
    tree = strip_database_ids(export_policy_tree(connection, root_id))
    validate_tree(tree, check_source=False)
    return tree
