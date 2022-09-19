import cpp

predicate func_0(Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_data_index")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_conn_index")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_sockindex_index")
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getRightOperand().(LTExpr).getType().hasName("int")
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_proxy_index")
		and target_0.getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(LogicalOrExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_1.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getType().hasName("int")
		and target_1.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_data_index")
		and target_1.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_1.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_conn_index")
		and target_1.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getRightOperand().(LTExpr).getType().hasName("int")
		and target_1.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_sockindex_index")
		and target_1.getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
and func_1(func)
select func
