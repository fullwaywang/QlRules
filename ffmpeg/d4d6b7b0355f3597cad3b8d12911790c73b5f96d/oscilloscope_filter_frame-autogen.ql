/**
 * @name ffmpeg-d4d6b7b0355f3597cad3b8d12911790c73b5f96d-oscilloscope_filter_frame
 * @id cpp/ffmpeg/d4d6b7b0355f3597cad3b8d12911790c73b5f96d/oscilloscope-filter-frame
 * @description ffmpeg-d4d6b7b0355f3597cad3b8d12911790c73b5f96d-libavfilter/vf_datascope.c-oscilloscope_filter_frame CVE-2020-22017
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_963, Variable voutlink_964, BlockStmt target_2, AddExpr target_3, AddressOfExpr target_4, FunctionCall target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="grid"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutlink_964
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_963, BlockStmt target_2, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="grid"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_963
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vs_963, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_fill_rectangle")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="draw"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gray"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="ox"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="oy"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

predicate func_3(Variable vs_963, AddExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
		and target_3.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="20"
		and target_3.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="statistics"
		and target_3.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
}

predicate func_4(Variable vs_963, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="draw"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_963
}

predicate func_5(Variable voutlink_964, FunctionCall target_5) {
		target_5.getTarget().hasName("ff_filter_frame")
		and target_5.getArgument(0).(VariableAccess).getTarget()=voutlink_964
}

from Function func, Variable vs_963, Variable voutlink_964, PointerFieldAccess target_1, BlockStmt target_2, AddExpr target_3, AddressOfExpr target_4, FunctionCall target_5
where
not func_0(vs_963, voutlink_964, target_2, target_3, target_4, target_5)
and func_1(vs_963, target_2, target_1)
and func_2(vs_963, target_2)
and func_3(vs_963, target_3)
and func_4(vs_963, target_4)
and func_5(voutlink_964, target_5)
and vs_963.getType().hasName("OscilloscopeContext *")
and voutlink_964.getType().hasName("AVFilterLink *")
and vs_963.getParentScope+() = func
and voutlink_964.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
