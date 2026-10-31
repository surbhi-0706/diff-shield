
def get_user(query):
    database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )
