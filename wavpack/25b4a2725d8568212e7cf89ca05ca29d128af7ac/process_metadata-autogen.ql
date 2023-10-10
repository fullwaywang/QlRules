/**
 * @name wavpack-25b4a2725d8568212e7cf89ca05ca29d128af7ac-process_metadata
 * @id cpp/wavpack/25b4a2725d8568212e7cf89ca05ca29d128af7ac/process-metadata
 * @description wavpack-25b4a2725d8568212e7cf89ca05ca29d128af7ac-src/open_utils.c-process_metadata CVE-2022-2476
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwpc_713, Parameter vwpmd_713, LogicalAndExpr target_12, ExprStmt target_14, ConditionalExpr target_16) {
	exists(ForStmt target_0 |
		target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue() instanceof Literal
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="byte_length"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_0.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getStmt().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_0.getStmt().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getStmt().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_0.getStmt().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="file_extension"
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_0.getStmt().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getRValue().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getRValue().(AssignExpr).getRValue() instanceof Literal
		and target_1.getEnclosingFunction() = func)
}

*/
/*predicate func_2(Parameter vwpc_713) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(VariableAccess).getType().hasName("int")
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="file_extension"
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713)
}

*/
/*predicate func_3(Parameter vwpc_713, Parameter vwpmd_713, ConditionalExpr target_16) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_3.getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="file_extension"
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="byte_length"
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vwpc_713, LogicalAndExpr target_12, ExprStmt target_18) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="file_extension"
		and target_4.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_4.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_4.getRValue().(Literal).getValue()="0"
		and target_4.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vwpc_713, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="file_extension"
		and target_5.getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vwpmd_713, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="data"
		and target_6.getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Parameter vwpmd_713, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="byte_length"
		and target_7.getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Parameter vwpmd_713, VariableAccess target_8) {
		target_8.getTarget()=vwpmd_713
}

predicate func_10(Parameter vwpc_713, Parameter vwpmd_713, FunctionCall target_10) {
		target_10.getTarget().hasName("memcpy")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="file_extension"
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_10.getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_10.getArgument(2).(PointerFieldAccess).getTarget().getName()="byte_length"
		and target_10.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
}

predicate func_11(Parameter vwpmd_713, ConditionalExpr target_16, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="byte_length"
		and target_11.getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_11.getQualifier().(VariableAccess).getLocation().isBefore(target_16.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Parameter vwpmd_713, LogicalAndExpr target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="byte_length"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_12.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="byte_length"
		and target_12.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_12.getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="8"
}

predicate func_14(Parameter vwpc_713, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="version_five"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_16(Parameter vwpmd_713, ConditionalExpr target_16) {
		target_16.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_16.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_16.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="32"
		and target_16.getThen().(Literal).getValue()="1"
		and target_16.getElse().(Literal).getValue()="0"
}

predicate func_18(Parameter vwpc_713, Parameter vwpmd_713, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="file_extension"
		and target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_713
		and target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="byte_length"
		and target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpmd_713
		and target_18.getExpr().(AssignExpr).getRValue() instanceof Literal
}

from Function func, Parameter vwpc_713, Parameter vwpmd_713, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, VariableAccess target_8, FunctionCall target_10, PointerFieldAccess target_11, LogicalAndExpr target_12, ExprStmt target_14, ConditionalExpr target_16, ExprStmt target_18
where
not func_0(vwpc_713, vwpmd_713, target_12, target_14, target_16)
and not func_4(vwpc_713, target_12, target_18)
and func_5(vwpc_713, target_5)
and func_6(vwpmd_713, target_6)
and func_7(vwpmd_713, target_7)
and func_8(vwpmd_713, target_8)
and func_10(vwpc_713, vwpmd_713, target_10)
and func_11(vwpmd_713, target_16, target_11)
and func_12(vwpmd_713, target_12)
and func_14(vwpc_713, target_14)
and func_16(vwpmd_713, target_16)
and func_18(vwpc_713, vwpmd_713, target_18)
and vwpc_713.getType().hasName("WavpackContext *")
and vwpmd_713.getType().hasName("WavpackMetadata *")
and vwpc_713.getParentScope+() = func
and vwpmd_713.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
