/**
 * @name linux-16c8d2df7ec0eed31b7d3b61cb13206a7fb930cc-loop_rw_iter
 * @id cpp/linux/16c8d2df7ec0eed31b7d3b61cb13206a7fb930cc/loop_rw_iter
 * @description linux-16c8d2df7ec0eed31b7d3b61cb13206a7fb930cc-loop_rw_iter 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Parameter vreq_3226, Variable vnr_3244) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_1.getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="rw"
		and target_1.getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_3226
		and target_1.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vnr_3244)
}

predicate func_2(Parameter vreq_3226, Variable vnr_3244) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="addr"
		and target_2.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="rw"
		and target_2.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_3226
		and target_2.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vnr_3244)
}

predicate func_3(Parameter viter_3226, Variable vnr_3244) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("iov_iter_advance")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=viter_3226
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnr_3244)
}

predicate func_4(Parameter viter_3226) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("iov_iter_iovec")
		and target_4.getArgument(0).(VariableAccess).getTarget()=viter_3226)
}

from Function func, Parameter vreq_3226, Parameter viter_3226, Variable vnr_3244
where
func_1(vreq_3226, vnr_3244)
and func_2(vreq_3226, vnr_3244)
and func_3(viter_3226, vnr_3244)
and vreq_3226.getType().hasName("io_kiocb *")
and viter_3226.getType().hasName("iov_iter *")
and func_4(viter_3226)
and vnr_3244.getType().hasName("ssize_t")
and vreq_3226.getParentScope+() = func
and viter_3226.getParentScope+() = func
and vnr_3244.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
