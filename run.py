from app import create_app

app = create_app()

if __name__ == "__main__":
    # Localhost only, HTTPS with the OpenSSL certificate, debugger disabled.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        ssl_context=("certs/cert.pem", "certs/key.pem"),
    )
