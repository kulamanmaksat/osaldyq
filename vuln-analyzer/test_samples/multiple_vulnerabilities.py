def vulnerable_function(user_input, filename):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)

    # Command Injection vulnerability
    os.system("cat " + filename)

    # XSS vulnerability
    html = "<div>" + user_input + "</div>"
    document.write(html)

    # Hardcoded credentials
    password = "super_secret_password123"
    api_key = "1234567890abcdef"

    # Unsafe deserialization
    data = pickle.loads(user_input)

    # Weak cryptography
    hash_value = hashlib.md5(password.encode()).hexdigest()

    # Unsafe file operations
    f = open("data/" + filename)
    content = f.read()

    return content 