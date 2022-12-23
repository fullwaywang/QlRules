/**
 * @name linux-e09463f220ca9a1a1ecfda84fcda658f99a1f12a-jbd2_journal_dirty_metadata
 * @id cpp/linux/e09463f220ca9a1a1ecfda84fcda658f99a1f12a/jbd2_journal_dirty_metadata
 * @description linux-e09463f220ca9a1a1ecfda84fcda658f99a1f12a-jbd2_journal_dirty_metadata CVE-2018-10883
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Variable vjh_1332, Variable vret_1333, Parameter vhandle_1328, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="h_buffer_credits"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhandle_1328
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1333
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="28"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="b_modified"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjh_1332
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="h_buffer_credits"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhandle_1328
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_2))
}

predicate func_3(Variable vjh_1332, Variable vret_1333, Parameter vhandle_1328) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="b_modified"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjh_1332
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="b_modified"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjh_1332
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="h_buffer_credits"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhandle_1328
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1333
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="28"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="h_buffer_credits"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhandle_1328)
}

predicate func_4(Parameter vbh_1328) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("jbd_lock_bh_state")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vbh_1328)
}

predicate func_5(Variable vtransaction_1330) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="t_journal"
		and target_5.getQualifier().(VariableAccess).getTarget()=vtransaction_1330)
}

predicate func_6(Variable vjh_1332, Variable v__func__) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("__jbd2_debug")
		and target_6.getArgument(0) instanceof Literal
		and target_6.getArgument(1) instanceof StringLiteral
		and target_6.getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_6.getArgument(3) instanceof Literal
		and target_6.getArgument(4).(StringLiteral).getValue()="journal_head %p\n"
		and target_6.getArgument(5).(VariableAccess).getTarget()=vjh_1332)
}

predicate func_7(Parameter vhandle_1328) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("is_handle_aborted")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vhandle_1328)
}

from Function func, Parameter vbh_1328, Variable vtransaction_1330, Variable vjh_1332, Variable vret_1333, Variable v__func__, Parameter vhandle_1328
where
not func_2(vjh_1332, vret_1333, vhandle_1328, func)
and func_3(vjh_1332, vret_1333, vhandle_1328)
and vbh_1328.getType().hasName("buffer_head *")
and func_4(vbh_1328)
and vtransaction_1330.getType().hasName("transaction_t *")
and func_5(vtransaction_1330)
and vjh_1332.getType().hasName("journal_head *")
and func_6(vjh_1332, v__func__)
and vret_1333.getType().hasName("int")
and v__func__.getType().hasName("const char[28]")
and vhandle_1328.getType().hasName("handle_t *")
and func_7(vhandle_1328)
and vbh_1328.getParentScope+() = func
and vtransaction_1330.getParentScope+() = func
and vjh_1332.getParentScope+() = func
and vret_1333.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vhandle_1328.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
