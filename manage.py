

def deploy():
    """Run deployment tasks."""
    from main import create_app, db
    from flask_migrate import upgrade, migrate, stamp

    main = create_app()
    main.app_context().push()

    # create database and tables
    db.create_all()

    # migrate database to latest revision
    stamp()
    migrate()
    upgrade()


deploy()
