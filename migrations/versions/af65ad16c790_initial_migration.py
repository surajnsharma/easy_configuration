"""Initial migration

Revision ID: af65ad16c790
Revises: 
Create Date: 2024-11-14 23:14:17.210383

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'af65ad16c790'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('_alembic_tmp_training_data')
    with op.batch_alter_table('training_data', schema=None) as batch_op:
        batch_op.alter_column('id',
               existing_type=sa.INTEGER(),
               nullable=False,
               autoincrement=True)
        batch_op.alter_column('category',
               existing_type=sa.TEXT(),
               type_=sa.String(length=255),
               existing_nullable=False)
        batch_op.alter_column('pattern',
               existing_type=sa.TEXT(),
               type_=sa.String(length=255),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('training_data', schema=None) as batch_op:
        batch_op.alter_column('pattern',
               existing_type=sa.String(length=255),
               type_=sa.TEXT(),
               existing_nullable=False)
        batch_op.alter_column('category',
               existing_type=sa.String(length=255),
               type_=sa.TEXT(),
               existing_nullable=False)
        batch_op.alter_column('id',
               existing_type=sa.INTEGER(),
               nullable=True,
               autoincrement=True)

    op.create_table('_alembic_tmp_training_data',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('pattern', sa.VARCHAR(length=255), nullable=False),
    sa.Column('suggestion', sa.TEXT(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('category', sa.VARCHAR(length=255), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###