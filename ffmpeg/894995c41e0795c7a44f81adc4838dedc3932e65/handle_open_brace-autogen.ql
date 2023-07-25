/**
 * @name ffmpeg-894995c41e0795c7a44f81adc4838dedc3932e65-handle_open_brace
 * @id cpp/ffmpeg/894995c41e0795c7a44f81adc4838dedc3932e65/handle-open-brace
 * @description ffmpeg-894995c41e0795c7a44f81adc4838dedc3932e65-libavcodec/htmlsubtitles.c-handle_open_brace CVE-2019-9721
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_51, Variable vin_52, FunctionCall target_0) {
		target_0.getTarget().hasName("sscanf")
		and not target_0.getTarget().hasName("scanbraces")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vin_52
		and target_0.getArgument(1).(StringLiteral).getValue()="{\\an%*1u}%n"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlen_51
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vlen_51, LogicalAndExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof FunctionCall
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_51
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(AssignAddExpr).getRValue() = target_2
}

predicate func_3(Variable vlen_51, VariableAccess target_3) {
		target_3.getTarget()=vlen_51
}

from Function func, Variable vlen_51, Variable vin_52, FunctionCall target_0, DeclStmt target_1, LogicalAndExpr target_2, VariableAccess target_3
where
func_0(vlen_51, vin_52, target_0)
and func_1(func, target_1)
and func_2(vlen_51, target_2)
and func_3(vlen_51, target_3)
and vlen_51.getType().hasName("int")
and vin_52.getType().hasName("const char *")
and vlen_51.getParentScope+() = func
and vin_52.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
