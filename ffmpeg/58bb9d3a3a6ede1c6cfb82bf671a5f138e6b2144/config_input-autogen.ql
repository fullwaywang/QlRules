/**
 * @name ffmpeg-58bb9d3a3a6ede1c6cfb82bf671a5f138e6b2144-config_input
 * @id cpp/ffmpeg/58bb9d3a3a6ede1c6cfb82bf671a5f138e6b2144/config-input
 * @description ffmpeg-58bb9d3a3a6ede1c6cfb82bf671a5f138e6b2144-libavfilter/af_tremolo.c-config_input CVE-2020-22026
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinlink_121, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="sample_rate"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinlink_121
}

predicate func_1(Variable vs_124, DivExpr target_8) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="table_size"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_1.getRValue() instanceof DivExpr
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_124, SubExpr target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="table"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc_array")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="table_size"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="8"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2)
		and target_9.getRightOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vs_124, NotExpr target_11) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="table_size"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_124
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vinlink_121, Variable vs_124, DivExpr target_5) {
		target_5.getLeftOperand().(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_5.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_121
		and target_5.getRightOperand().(PointerFieldAccess).getTarget().getName()="freq"
		and target_5.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc_array")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="8"
}

predicate func_6(Variable vs_124, VariableAccess target_6) {
		target_6.getTarget()=vs_124
}

predicate func_7(Parameter vinlink_121, Variable vs_124, BlockStmt target_12, DivExpr target_7) {
		target_7.getLeftOperand().(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_7.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_121
		and target_7.getRightOperand().(PointerFieldAccess).getTarget().getName()="freq"
		and target_7.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_7.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_12
}

predicate func_8(Parameter vinlink_121, Variable vs_124, DivExpr target_8) {
		target_8.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="freq"
		and target_8.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_8.getRightOperand().(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_8.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_121
}

predicate func_9(Variable vs_124, SubExpr target_9) {
		target_9.getLeftOperand().(Literal).getValue()="1.0"
		and target_9.getRightOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_9.getRightOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_9.getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="2.0"
}

predicate func_11(Variable vs_124, NotExpr target_11) {
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="table"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
}

predicate func_12(Variable vs_124, BlockStmt target_12) {
		target_12.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sin")
		and target_12.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getValue()="6.283185307179586232"
		and target_12.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("fmod")
		and target_12.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1.0"
		and target_12.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="table"
		and target_12.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_124
		and target_12.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1"
		and target_12.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(FunctionCall).getTarget().hasName("fabs")
}

from Function func, Parameter vinlink_121, Variable vs_124, PointerFieldAccess target_0, DivExpr target_5, VariableAccess target_6, DivExpr target_7, DivExpr target_8, SubExpr target_9, NotExpr target_11, BlockStmt target_12
where
func_0(vinlink_121, target_0)
and not func_1(vs_124, target_8)
and not func_2(vs_124, target_9, func)
and not func_4(vs_124, target_11)
and func_5(vinlink_121, vs_124, target_5)
and func_6(vs_124, target_6)
and func_7(vinlink_121, vs_124, target_12, target_7)
and func_8(vinlink_121, vs_124, target_8)
and func_9(vs_124, target_9)
and func_11(vs_124, target_11)
and func_12(vs_124, target_12)
and vinlink_121.getType().hasName("AVFilterLink *")
and vs_124.getType().hasName("TremoloContext *")
and vinlink_121.getParentScope+() = func
and vs_124.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
