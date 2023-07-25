/**
 * @name freerdp-52dd312e11b7376db62eabda244b481386d28c86-urbdrc_process_io_control
 * @id cpp/freerdp/52dd312e11b7376db62eabda244b481386d28c86/urbdrc-process-io-control
 * @description freerdp-52dd312e11b7376db62eabda244b481386d28c86-channels/urbdrc/client/data_transfer.c-urbdrc_process_io_control CVE-2020-11039
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

predicate func_1(Parameter vs_210, Variable vInputBufferSize_215, ReturnStmt target_8, RelationalOperation target_9) {
	exists(NotExpr target_1 |
		target_1.getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_210
		and target_1.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vInputBufferSize_215
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vs_210, ExprStmt target_11, ExprStmt target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_210
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_2)
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vs_210, VariableAccess target_4) {
		target_4.getTarget()=vs_210
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Variable vInputBufferSize_215, VariableAccess target_5) {
		target_5.getTarget()=vInputBufferSize_215
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vs_210, Variable vInputBufferSize_215, ReturnStmt target_8, AddExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vInputBufferSize_215
		and target_6.getAnOperand() instanceof Literal
		and target_6.getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_6.getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_210
		and target_6.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_7(Parameter vs_210, Variable vInputBufferSize_215, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_210
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vInputBufferSize_215
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="13"
}

predicate func_9(Parameter vs_210, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_210
		and target_9.getGreaterOperand() instanceof AddExpr
}

predicate func_11(Parameter vs_210, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_210
		and target_11.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
}

from Function func, Parameter vs_210, Variable vInputBufferSize_215, Literal target_0, VariableAccess target_4, VariableAccess target_5, AddExpr target_6, ExprStmt target_7, ReturnStmt target_8, RelationalOperation target_9, ExprStmt target_11
where
func_0(func, target_0)
and not func_1(vs_210, vInputBufferSize_215, target_8, target_9)
and not func_2(vs_210, target_11, target_7, func)
and func_4(vs_210, target_4)
and func_5(vInputBufferSize_215, target_5)
and func_6(vs_210, vInputBufferSize_215, target_8, target_6)
and func_7(vs_210, vInputBufferSize_215, func, target_7)
and func_8(target_8)
and func_9(vs_210, target_9)
and func_11(vs_210, target_11)
and vs_210.getType().hasName("wStream *")
and vInputBufferSize_215.getType().hasName("UINT32")
and vs_210.getParentScope+() = func
and vInputBufferSize_215.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
