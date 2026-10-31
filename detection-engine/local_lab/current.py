def get_user(query):
    print("Fetching user")
    database.execute(
        "SELECT * FROM users WHERE name = ?",
        (query,)
    )