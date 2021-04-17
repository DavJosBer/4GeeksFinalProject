"""empty message

Revision ID: 96fe0ca9bda3
Revises: 2784e2fd01a5
Create Date: 2021-04-17 16:07:55.973555

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '96fe0ca9bda3'
down_revision = '2784e2fd01a5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('factura',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('total', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['service.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('factura')
    # ### end Alembic commands ###