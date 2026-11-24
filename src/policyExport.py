"""Export stored policy rows as a tree, retaining database IDs."""
from .policyTree import COLUMNS


def export_policy_tree(connection, root_id):
    """Read a consistent tree in one query; expose parent as parent_id."""
    with connection.cursor() as cursor:
        cursor.execute('''WITH RECURSIVE tree AS (
            SELECT p.*, ARRAY[p.id] AS visited FROM policy p WHERE id=%s
            UNION ALL
            SELECT p.*, t.visited || p.id FROM policy p JOIN tree t ON p.parent=t.id
            WHERE NOT p.id=ANY(t.visited))
            SELECT id, parent, ''' + ', '.join(f'"{column}"' for column in COLUMNS)
                       + ' FROM tree ORDER BY id', (root_id,))
        rows = cursor.fetchall()
    if not rows:
        raise ValueError(f'Policy root {root_id} not found')
    nodes = {row[0]: dict(id=row[0], parent_id=row[1],
                         **dict(zip(COLUMNS, row[2:])), children=[]) for row in rows}
    for row in rows:
        if row[0] != root_id:
            nodes[row[1]]['children'].append(nodes[row[0]])
    return nodes[root_id]
