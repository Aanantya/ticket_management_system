from app import create_app

try:
    app = create_app()
except Exception as e:
    print(f'Error creating app, {e}')

if __name__ == '__main__':
    app.run()