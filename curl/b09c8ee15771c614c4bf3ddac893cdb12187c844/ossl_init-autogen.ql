/**
 * @name curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-ossl_init
 * @id cpp/curl/b09c8ee15771c614c4bf3ddac893cdb12187c844/ossl-init
 * @description curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-ossl_init CVE-2021-22890
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_proxy_index")
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_data_index")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_conn_index")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ossl_get_ssl_sockindex_index")
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
and func_1(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
