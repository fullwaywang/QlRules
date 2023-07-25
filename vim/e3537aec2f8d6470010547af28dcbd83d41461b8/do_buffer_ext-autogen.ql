/**
 * @name vim-e3537aec2f8d6470010547af28dcbd83d41461b8-do_buffer_ext
 * @id cpp/vim/e3537aec2f8d6470010547af28dcbd83d41461b8/do-buffer-ext
 * @description vim-e3537aec2f8d6470010547af28dcbd83d41461b8-src/buffer.c-do_buffer_ext CVE-2022-0554
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_1233, ExprStmt target_7, EqualityOperation target_8, LogicalOrExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("bt_quickfix")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1233
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_1233, BlockStmt target_9, ExprStmt target_10, LogicalAndExpr target_5) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof LogicalAndExpr
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("bt_quickfix")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1233
		and target_1.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbuf_1233, BreakStmt target_11, AssignExpr target_12, LogicalAndExpr target_6) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof LogicalAndExpr
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("bt_quickfix")
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1233
		and target_2.getParent().(IfStmt).getThen()=target_11
		and target_12.getLValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vbuf_1233, EqualityOperation target_13, ExprStmt target_14, EqualityOperation target_15) {
	exists(IfStmt target_3 |
		target_3.getCondition().(FunctionCall).getTarget().hasName("bt_quickfix")
		and target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1233
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1233
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vbuf_1233, Variable vcurbuf, ExprStmt target_7, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_1233
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcurbuf
		and target_4.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_p_bl"
		and target_4.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1233
		and target_4.getParent().(IfStmt).getThen()=target_7
}

predicate func_5(Variable vbuf_1233, Variable vcurbuf, BlockStmt target_9, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="b_help"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1233
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="b_help"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="b_p_bl"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1233
		and target_5.getParent().(IfStmt).getThen()=target_9
}

predicate func_6(Variable vbuf_1233, Variable vcurbuf, BreakStmt target_11, LogicalAndExpr target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="b_p_bl"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1233
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_1233
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcurbuf
		and target_6.getParent().(IfStmt).getThen()=target_11
}

predicate func_7(Variable vbuf_1233, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1233
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vbuf_1233, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vbuf_1233
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vbuf_1233, BlockStmt target_9) {
		target_9.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ml_mfp"
		and target_9.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_9.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1233
		and target_9.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
}

predicate func_10(Variable vbuf_1233, Variable vcurbuf, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1233
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="b_prev"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
}

predicate func_11(BreakStmt target_11) {
		target_11.toString() = "break;"
}

predicate func_12(Variable vbuf_1233, AssignExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget()=vbuf_1233
		and target_12.getRValue().(PointerFieldAccess).getTarget().getName()="b_next"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1233
}

predicate func_13(Variable vbuf_1233, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vbuf_1233
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vbuf_1233, Variable vcurbuf, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1233
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="b_prev"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
}

predicate func_15(Variable vbuf_1233, EqualityOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vbuf_1233
		and target_15.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vbuf_1233, Variable vcurbuf, LogicalOrExpr target_4, LogicalAndExpr target_5, LogicalAndExpr target_6, ExprStmt target_7, EqualityOperation target_8, BlockStmt target_9, ExprStmt target_10, BreakStmt target_11, AssignExpr target_12, EqualityOperation target_13, ExprStmt target_14, EqualityOperation target_15
where
not func_0(vbuf_1233, target_7, target_8, target_4)
and not func_1(vbuf_1233, target_9, target_10, target_5)
and not func_2(vbuf_1233, target_11, target_12, target_6)
and not func_3(vbuf_1233, target_13, target_14, target_15)
and func_4(vbuf_1233, vcurbuf, target_7, target_4)
and func_5(vbuf_1233, vcurbuf, target_9, target_5)
and func_6(vbuf_1233, vcurbuf, target_11, target_6)
and func_7(vbuf_1233, target_7)
and func_8(vbuf_1233, target_8)
and func_9(vbuf_1233, target_9)
and func_10(vbuf_1233, vcurbuf, target_10)
and func_11(target_11)
and func_12(vbuf_1233, target_12)
and func_13(vbuf_1233, target_13)
and func_14(vbuf_1233, vcurbuf, target_14)
and func_15(vbuf_1233, target_15)
and vbuf_1233.getType().hasName("buf_T *")
and vcurbuf.getType().hasName("buf_T *")
and vbuf_1233.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
