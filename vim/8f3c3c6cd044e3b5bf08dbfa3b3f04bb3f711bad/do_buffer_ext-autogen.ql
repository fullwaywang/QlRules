/**
 * @name vim-8f3c3c6cd044e3b5bf08dbfa3b3f04bb3f711bad-do_buffer_ext
 * @id cpp/vim/8f3c3c6cd044e3b5bf08dbfa3b3f04bb3f711bad/do-buffer-ext
 * @description vim-8f3c3c6cd044e3b5bf08dbfa3b3f04bb3f711bad-src/buffer.c-do_buffer_ext CVE-2022-3591
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vaction_1260, Parameter vcount_1263, Variable vbuf_1266, Variable ve_buffer_nr_does_not_exist, LogicalOrExpr target_1, LogicalAndExpr target_2, ExprStmt target_3, LogicalAndExpr target_4, NotExpr target_5, FunctionCall target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="b_flags"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1266
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="128"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("semsg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_buffer_nr_does_not_exist
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcount_1263
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vaction_1260, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
}

predicate func_2(Parameter vaction_1260, Variable vbuf_1266, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vaction_1260
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ml_mfp"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1266
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_p_bl"
		and target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1266
}

predicate func_3(Parameter vcount_1263, Variable ve_buffer_nr_does_not_exist, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("semsg")
		and target_3.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_3.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_buffer_nr_does_not_exist
		and target_3.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcount_1263
}

predicate func_4(Variable vbuf_1266, LogicalAndExpr target_4) {
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("bt_popup")
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1266
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("bt_terminal")
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1266
}

predicate func_5(Variable vbuf_1266, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("can_unload_buffer")
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1266
}

predicate func_6(Variable ve_buffer_nr_does_not_exist, FunctionCall target_6) {
		target_6.getTarget().hasName("dcgettext")
		and target_6.getArgument(0).(Literal).getValue()="0"
		and target_6.getArgument(1).(VariableAccess).getTarget()=ve_buffer_nr_does_not_exist
		and target_6.getArgument(2).(Literal).getValue()="5"
}

from Function func, Parameter vaction_1260, Parameter vcount_1263, Variable vbuf_1266, Variable ve_buffer_nr_does_not_exist, LogicalOrExpr target_1, LogicalAndExpr target_2, ExprStmt target_3, LogicalAndExpr target_4, NotExpr target_5, FunctionCall target_6
where
not func_0(vaction_1260, vcount_1263, vbuf_1266, ve_buffer_nr_does_not_exist, target_1, target_2, target_3, target_4, target_5, target_6, func)
and func_1(vaction_1260, target_1)
and func_2(vaction_1260, vbuf_1266, target_2)
and func_3(vcount_1263, ve_buffer_nr_does_not_exist, target_3)
and func_4(vbuf_1266, target_4)
and func_5(vbuf_1266, target_5)
and func_6(ve_buffer_nr_does_not_exist, target_6)
and vaction_1260.getType().hasName("int")
and vcount_1263.getType().hasName("int")
and vbuf_1266.getType().hasName("buf_T *")
and ve_buffer_nr_does_not_exist.getType() instanceof ArrayType
and vaction_1260.getParentScope+() = func
and vcount_1263.getParentScope+() = func
and vbuf_1266.getParentScope+() = func
and not ve_buffer_nr_does_not_exist.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
