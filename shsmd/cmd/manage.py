import click
from shsmd.api import app
from shsmd.db.mysql import create_schema
from shsmd.db.mysql import drop_schema

@click.command()
@click.option('--initschema', is_flag=True)
@click.option('--dropschema', is_flag=True)
def main(initschema, dropschema):
    if dropschema:
        print "Dropping all tables from database."
        drop_schema()

    if initschema:
        print "Creating shsmd tables from schema."
        create_schema()
