/**
 * @name linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_wq_create
 * @id cpp/linux/181e448d8709e517c9c7b523fcd209f24eb38ca7/io-wq-create
 * @description linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_wq_create 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwq_980) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="168"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vwq_980)
}

predicate func_1(Parameter vdata_977, Variable vwq_980, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="creds"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwq_980
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="creds"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_977
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vdata_977) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="user"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdata_977)
}

predicate func_3(Variable vwq_980) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="user"
		and target_3.getQualifier().(VariableAccess).getTarget()=vwq_980)
}

from Function func, Parameter vdata_977, Variable vwq_980
where
func_0(vwq_980)
and not func_1(vdata_977, vwq_980, func)
and vdata_977.getType().hasName("io_wq_data *")
and func_2(vdata_977)
and vwq_980.getType().hasName("io_wq *")
and func_3(vwq_980)
and vdata_977.getParentScope+() = func
and vwq_980.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
