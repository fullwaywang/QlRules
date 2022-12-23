/**
 * @name linux-d785a773bed966a75ca1f11d108ae1897189975b-io_files_update_with_index_alloc
 * @id cpp/linux/d785a773bed966a75ca1f11d108ae1897189975b/io_files_update_with_index_alloc
 * @description linux-d785a773bed966a75ca1f11d108ae1897189975b-io_files_update_with_index_alloc 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vreq_7968, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="file_data"
		and target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_7968
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-6"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="6"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vreq_7968) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="(unknown field)"
		and target_1.getQualifier().(VariableAccess).getTarget()=vreq_7968)
}

from Function func, Parameter vreq_7968
where
not func_0(vreq_7968, func)
and vreq_7968.getType().hasName("io_kiocb *")
and func_1(vreq_7968)
and vreq_7968.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
