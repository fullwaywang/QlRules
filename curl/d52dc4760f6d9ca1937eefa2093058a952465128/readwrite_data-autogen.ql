/**
 * @name curl-d52dc4760f6d9ca1937eefa2093058a952465128-readwrite_data
 * @id cpp/curl/d52dc4760f6d9ca1937eefa2093058a952465128/readwrite-data
 * @description curl-d52dc4760f6d9ca1937eefa2093058a952465128-lib/transfer.c-readwrite_data CVE-2018-1000122
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_438, Parameter vk_440, Variable vexcess_446, LogicalAndExpr target_7, ValueFieldAccess target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="str"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vexcess_446
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="buffer_size"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_438
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexcess_446
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="str"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vk_440, Variable vexcess_446, ExprStmt target_9, ExprStmt target_11, LogicalAndExpr target_7) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="str"
		and target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_1.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vexcess_446
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_1.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_2(Parameter vdata_438, Parameter vk_440, ValueFieldAccess target_8, ExprStmt target_13) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="buffer_size"
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_438
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vconn_439, Variable vexcess_446, BlockStmt target_14, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="readwrite"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_439
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexcess_446
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stream_was_rewound"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_439
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
}

/*predicate func_4(Parameter vconn_439, NotExpr target_4) {
		target_4.getOperand().(ValueFieldAccess).getTarget().getName()="stream_was_rewound"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_439
}

*/
/*predicate func_5(Variable vexcess_446, VariableAccess target_5) {
		target_5.getTarget()=vexcess_446
}

*/
predicate func_7(Parameter vconn_439, Variable vexcess_446, LogicalAndExpr target_7) {
		target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="readwrite"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_439
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexcess_446
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof NotExpr
}

predicate func_8(Parameter vdata_438, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="headerbuff"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_438
}

predicate func_9(Parameter vk_440, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="badheader"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
}

predicate func_10(Parameter vk_440, ExprStmt target_10) {
		target_10.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="keepon"
		and target_10.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_10.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="1"
}

predicate func_11(Parameter vdata_438, Parameter vk_440, Variable vexcess_446, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_438
		and target_11.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Excess found in a non pipelined read: excess = %zu, size = %ld, maxdownload = %ld, bytecount = %ld\n"
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexcess_446
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_11.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="maxdownload"
		and target_11.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_11.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="bytecount"
		and target_11.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
}

predicate func_12(Variable vexcess_446, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexcess_446
}

predicate func_13(Parameter vk_440, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="str"
		and target_13.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
}

predicate func_14(Parameter vdata_438, Parameter vconn_439, Parameter vk_440, Variable vexcess_446, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="str"
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vk_440
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexcess_446
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="readwrite"
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_439
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_438
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vconn_439
}

from Function func, Parameter vdata_438, Parameter vconn_439, Parameter vk_440, Variable vexcess_446, PointerFieldAccess target_3, LogicalAndExpr target_7, ValueFieldAccess target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, BlockStmt target_14
where
not func_0(vdata_438, vk_440, vexcess_446, target_7, target_8, target_9, target_10, target_11, target_12)
and func_3(vconn_439, vexcess_446, target_14, target_3)
and func_7(vconn_439, vexcess_446, target_7)
and func_8(vdata_438, target_8)
and func_9(vk_440, target_9)
and func_10(vk_440, target_10)
and func_11(vdata_438, vk_440, vexcess_446, target_11)
and func_12(vexcess_446, target_12)
and func_13(vk_440, target_13)
and func_14(vdata_438, vconn_439, vk_440, vexcess_446, target_14)
and vdata_438.getType().hasName("Curl_easy *")
and vconn_439.getType().hasName("connectdata *")
and vk_440.getType().hasName("SingleRequest *")
and vexcess_446.getType().hasName("size_t")
and vdata_438.getParentScope+() = func
and vconn_439.getParentScope+() = func
and vk_440.getParentScope+() = func
and vexcess_446.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
