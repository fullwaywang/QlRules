/**
 * @name freerdp-52dd312e11b7376db62eabda244b481386d28c86-urbdrc_process_internal_io_control
 * @id cpp/freerdp/52dd312e11b7376db62eabda244b481386d28c86/urbdrc-process-internal-io-control
 * @description freerdp-52dd312e11b7376db62eabda244b481386d28c86-channels/urbdrc/client/data_transfer.c-urbdrc_process_internal_io_control CVE-2020-11039
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="8"
		and not target_0.getValue()="13"
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand() instanceof AddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vInputBufferSize_306, Parameter vs_303, ReturnStmt target_8, RelationalOperation target_10) {
	exists(NotExpr target_1 |
		target_1.getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_303
		and target_1.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vInputBufferSize_306
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_10.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vs_303, ExprStmt target_12, ExprStmt target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_303
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_2)
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vs_303, VariableAccess target_4) {
		target_4.getTarget()=vs_303
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Variable vInputBufferSize_306, VariableAccess target_5) {
		target_5.getTarget()=vInputBufferSize_306
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Variable vInputBufferSize_306, Parameter vs_303, ReturnStmt target_8, AddExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vInputBufferSize_306
		and target_6.getAnOperand() instanceof Literal
		and target_6.getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_6.getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_303
		and target_6.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_7(Variable vInputBufferSize_306, Parameter vs_303, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_303
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vInputBufferSize_306
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="13"
}

predicate func_10(Parameter vs_303, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_10.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_303
		and target_10.getGreaterOperand() instanceof AddExpr
}

predicate func_12(Parameter vs_303, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_303
		and target_12.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_12.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vInputBufferSize_306, Parameter vs_303, Literal target_0, VariableAccess target_4, VariableAccess target_5, AddExpr target_6, ExprStmt target_7, ReturnStmt target_8, RelationalOperation target_10, ExprStmt target_12
where
func_0(func, target_0)
and not func_1(vInputBufferSize_306, vs_303, target_8, target_10)
and not func_2(vs_303, target_12, target_7, func)
and func_4(vs_303, target_4)
and func_5(vInputBufferSize_306, target_5)
and func_6(vInputBufferSize_306, vs_303, target_8, target_6)
and func_7(vInputBufferSize_306, vs_303, func, target_7)
and func_8(target_8)
and func_10(vs_303, target_10)
and func_12(vs_303, target_12)
and vInputBufferSize_306.getType().hasName("UINT32")
and vs_303.getType().hasName("wStream *")
and vInputBufferSize_306.getParentScope+() = func
and vs_303.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
