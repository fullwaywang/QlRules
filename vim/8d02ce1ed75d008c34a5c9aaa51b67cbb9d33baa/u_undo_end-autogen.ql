/**
 * @name vim-8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa-u_undo_end
 * @id cpp/vim/8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa/u-undo-end
 * @description vim-8d02ce1ed75d008c34a5c9aaa51b67cbb9d33baa-src/undo.c-u_undo_end CVE-2022-0368
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurbuf, LogicalAndExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("check_pos")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurbuf
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("pos_T")
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurbuf, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcurbuf
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="wo_cole"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_onebuf_opt"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

from Function func, Variable vcurbuf, LogicalAndExpr target_1
where
not func_0(vcurbuf, target_1, func)
and func_1(vcurbuf, target_1)
and vcurbuf.getType().hasName("buf_T *")
and not vcurbuf.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
