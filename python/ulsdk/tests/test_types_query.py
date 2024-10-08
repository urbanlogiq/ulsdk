# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.query import *

def test_all_columns():
    _t0 = AllColumns.make_default()
    _b = _t0.to_bytes()
    _t1 = AllColumns.from_bytes(_b)
    assert _t0 == _t1
def test_arrow():
    _t0 = Arrow.make_default()
    _b = _t0.to_bytes()
    _t1 = Arrow.from_bytes(_b)
    assert _t0 == _t1
def test_binary_query_element():
    _t0 = BinaryQueryElement.make_default()
    _b = _t0.to_bytes()
    _t1 = BinaryQueryElement.from_bytes(_b)
    assert _t0 == _t1
def test_case():
    _t0 = Case.make_default()
    _b = _t0.to_bytes()
    _t1 = Case.from_bytes(_b)
    assert _t0 == _t1
def test_column():
    _t0 = Column.make_default()
    _b = _t0.to_bytes()
    _t1 = Column.from_bytes(_b)
    assert _t0 == _t1
def test_data_catalog():
    _t0 = DataCatalog.make_default()
    _b = _t0.to_bytes()
    _t1 = DataCatalog.from_bytes(_b)
    assert _t0 == _t1
def test_delete_query_element():
    _t0 = DeleteQueryElement.make_default()
    _b = _t0.to_bytes()
    _t1 = DeleteQueryElement.from_bytes(_b)
    assert _t0 == _t1
def test_distinct():
    _t0 = Distinct.make_default()
    _b = _t0.to_bytes()
    _t1 = Distinct.from_bytes(_b)
    assert _t0 == _t1
def test_expr():
    _t0 = Expr.make_default()
    _b = _t0.to_bytes()
    _t1 = Expr.from_bytes(_b)
    assert _t0 == _t1
def test_function():
    _t0 = Function.make_default()
    _b = _t0.to_bytes()
    _t1 = Function.from_bytes(_b)
    assert _t0 == _t1
def test_join():
    _t0 = Join.make_default()
    _b = _t0.to_bytes()
    _t1 = Join.from_bytes(_b)
    assert _t0 == _t1
def test_mvdb_subcollection():
    _t0 = MvdbSubcollection.make_default()
    _b = _t0.to_bytes()
    _t1 = MvdbSubcollection.from_bytes(_b)
    assert _t0 == _t1
def test_nullable_uint():
    _t0 = NullableUint.make_default()
    _b = _t0.to_bytes()
    _t1 = NullableUint.from_bytes(_b)
    assert _t0 == _t1
def test_order_by_expr():
    _t0 = OrderByExpr.make_default()
    _b = _t0.to_bytes()
    _t1 = OrderByExpr.from_bytes(_b)
    assert _t0 == _t1
def test_parameter():
    _t0 = Parameter.make_default()
    _b = _t0.to_bytes()
    _t1 = Parameter.from_bytes(_b)
    assert _t0 == _t1
def test_parameter_instance():
    _t0 = ParameterInstance.make_default()
    _b = _t0.to_bytes()
    _t1 = ParameterInstance.from_bytes(_b)
    assert _t0 == _t1
def test_parameterized_query():
    _t0 = ParameterizedQuery.make_default()
    _b = _t0.to_bytes()
    _t1 = ParameterizedQuery.from_bytes(_b)
    assert _t0 == _t1
def test_partition():
    _t0 = Partition.make_default()
    _b = _t0.to_bytes()
    _t1 = Partition.from_bytes(_b)
    assert _t0 == _t1
def test_query():
    _t0 = Query.make_default()
    _b = _t0.to_bytes()
    _t1 = Query.from_bytes(_b)
    assert _t0 == _t1
def test_query_element():
    _t0 = QueryElement.make_default()
    _b = _t0.to_bytes()
    _t1 = QueryElement.from_bytes(_b)
    assert _t0 == _t1
def test_query_table_source():
    _t0 = QueryTableSource.make_default()
    _b = _t0.to_bytes()
    _t1 = QueryTableSource.from_bytes(_b)
    assert _t0 == _t1
def test_record_batch_placeholder():
    _t0 = RecordBatchPlaceholder.make_default()
    _b = _t0.to_bytes()
    _t1 = RecordBatchPlaceholder.from_bytes(_b)
    assert _t0 == _t1
def test_set_expr():
    _t0 = SetExpr.make_default()
    _b = _t0.to_bytes()
    _t1 = SetExpr.from_bytes(_b)
    assert _t0 == _t1
def test_table_order_by():
    _t0 = TableOrderBy.make_default()
    _b = _t0.to_bytes()
    _t1 = TableOrderBy.from_bytes(_b)
    assert _t0 == _t1
def test_table_source():
    _t0 = TableSource.make_default()
    _b = _t0.to_bytes()
    _t1 = TableSource.from_bytes(_b)
    assert _t0 == _t1
def test_unary_query_element():
    _t0 = UnaryQueryElement.make_default()
    _b = _t0.to_bytes()
    _t1 = UnaryQueryElement.from_bytes(_b)
    assert _t0 == _t1
def test_unset_argument():
    _t0 = UnsetArgument.make_default()
    _b = _t0.to_bytes()
    _t1 = UnsetArgument.from_bytes(_b)
    assert _t0 == _t1
def test_update_query_element():
    _t0 = UpdateQueryElement.make_default()
    _b = _t0.to_bytes()
    _t1 = UpdateQueryElement.from_bytes(_b)
    assert _t0 == _t1
def test_value_index():
    _t0 = ValueIndex.make_default()
    _b = _t0.to_bytes()
    _t1 = ValueIndex.from_bytes(_b)
    assert _t0 == _t1
def test_vector():
    _t0 = Vector.make_default()
    _b = _t0.to_bytes()
    _t1 = Vector.from_bytes(_b)
    assert _t0 == _t1
def test_when():
    _t0 = When.make_default()
    _b = _t0.to_bytes()
    _t1 = When.from_bytes(_b)
    assert _t0 == _t1
def test_window():
    _t0 = Window.make_default()
    _b = _t0.to_bytes()
    _t1 = Window.from_bytes(_b)
    assert _t0 == _t1
def test_worklog_subcollection():
    _t0 = WorklogSubcollection.make_default()
    _b = _t0.to_bytes()
    _t1 = WorklogSubcollection.from_bytes(_b)
    assert _t0 == _t1