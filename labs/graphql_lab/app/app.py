#!/usr/bin/env python3
"""GraphQL Lab - Vulnerable GraphQL API for testing.

This intentionally vulnerable application demonstrates GraphQL vulnerabilities:
- Introspection enabled
- Depth-based DoS
- Query complexity issues
- Field injection

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify
import graphene

app = Flask(__name__)

# Mock data
USERS = [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"},
]

POSTS = [
    {"id": 1, "title": "Post 1", "author_id": 1},
    {"id": 2, "title": "Post 2", "author_id": 2},
]

# GraphQL Schema
class User(graphene.ObjectType):
    id = graphene.Int()
    name = graphene.String()
    email = graphene.String()
    posts = graphene.List(lambda: Post)

    def resolve_posts(self, info):
        # VULNERABLE: No depth/complexity limits
        return [p for p in POSTS if p['author_id'] == self.id]


class Post(graphene.ObjectType):
    id = graphene.Int()
    title = graphene.String()
    author = graphene.Field(User)

    def resolve_author(self, info):
        # VULNERABLE: Recursive resolution without limits
        user = next((u for u in USERS if u['id'] == self['author_id']), None)
        return user


class Query(graphene.ObjectType):
    # VULNERABLE: Introspection enabled by default
    users = graphene.List(User)
    user = graphene.Field(User, id=graphene.Int())
    posts = graphene.List(Post)
    post = graphene.Field(Post, id=graphene.Int())

    def resolve_users(self, info):
        return USERS

    def resolve_user(self, info, id):
        return next((u for u in USERS if u['id'] == id), None)

    def resolve_posts(self, info):
        return POSTS

    def resolve_post(self, info, id):
        return next((p for p in POSTS if p['id'] == id), None)


schema = graphene.Schema(query=Query)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>GraphQL Lab</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>GraphQL Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h2>GraphQL Testing Lab</h2>
        <p>This lab contains intentional GraphQL vulnerabilities:</p>
        <ul>
            <li><a href="/graphql">GraphQL Endpoint</a> - POST queries here</li>
            <li>Introspection enabled</li>
            <li>No depth/complexity limits</li>
            <li>Recursive queries allowed</li>
        </ul>
        <h3>Example Vulnerable Query:</h3>
        <pre>
query {{
  users {{
    id
    name
    posts {{
      id
      title
      author {{
        id
        name
        posts {{
          id
          author {{
            id
            posts {{
              id
            }}
          }}
        }}
      }}
    }}
  }}
}}
        </pre>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/graphql', methods=['GET', 'POST'])
def graphql():
    """VULNERABLE: GraphQL endpoint with no limits"""
    if request.method == 'GET':
        # Return GraphiQL-like interface
        return BASE_TEMPLATE.replace('{content}', """
            <h2>GraphQL Endpoint</h2>
            <p>POST GraphQL queries to this endpoint</p>
            <form method="POST">
                <textarea name="query" rows="10" cols="80">query { users { id name } }</textarea>
                <br><button type="submit">Execute</button>
            </form>
        """)
    
    # Handle GraphQL query
    data = request.get_json() or {}
    query = data.get('query') or request.form.get('query', '')
    
    if not query:
        return jsonify({"error": "No query provided"}), 400
    
    try:
        # VULNERABLE: Execute query without depth/complexity limits
        result = schema.execute(query)
        return jsonify({
            "data": result.data,
            "errors": [str(e) for e in result.errors] if result.errors else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
