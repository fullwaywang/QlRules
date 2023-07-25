/**
 * @name vim-dc5490e2cbc8c16022a23b449b48c1bd0083f366-ex_copy
 * @id cpp/vim/dc5490e2cbc8c16022a23b449b48c1bd0083f366/ex-copy
 * @description vim-dc5490e2cbc8c16022a23b449b48c1bd0083f366-src/ex_cmds.c-ex_copy CVE-2022-0361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurbuf, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("check_pos")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurbuf
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("pos_T")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurbuf, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_start"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_end"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vcurbuf, ExprStmt target_1
where
not func_0(vcurbuf, target_1, func)
and func_1(vcurbuf, target_1)
and vcurbuf.getType().hasName("buf_T *")
and not vcurbuf.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
