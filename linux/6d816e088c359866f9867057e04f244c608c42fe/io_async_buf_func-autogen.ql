/**
 * @name linux-6d816e088c359866f9867057e04f244c608c42fe-io_async_buf_func
 * @id cpp/linux/6d816e088c359866f9867057e04f244c608c42fe/io_async_buf_func
 * @description linux-6d816e088c359866f9867057e04f244c608c42fe-io_async_buf_func 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vreq_3024, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("percpu_ref_get")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="refs"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_3024
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Variable vreq_3024) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="task_work"
		and target_1.getQualifier().(VariableAccess).getTarget()=vreq_3024)
}

from Function func, Variable vreq_3024
where
not func_0(vreq_3024, func)
and vreq_3024.getType().hasName("io_kiocb *")
and func_1(vreq_3024)
and vreq_3024.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
