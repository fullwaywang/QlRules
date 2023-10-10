/**
 * @name freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-rdg_receive_packet
 * @id cpp/freerdp/6b485b146a1b9d6ce72dfd7b5f36456c166e7a16/rdg-receive-packet
 * @description freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-libfreerdp/core/gateway/rdg.c-rdg_receive_packet CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vheader_290, Variable vpacketLength_291, BlockStmt target_2, NotExpr target_3, PointerArithmeticOperation target_4, ExprStmt target_5, LogicalOrExpr target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vpacketLength_291
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vheader_290
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_289, Variable vpacketLength_291, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpacketLength_291
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_EnsureCapacity")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_289
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacketLength_291
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vs_289, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_289
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_3(Variable vs_289, Variable vheader_290, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("rdg_read_all")
		and target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tlsOut"
		and target_3.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("Stream_Buffer")
		and target_3.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_289
		and target_3.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vheader_290
}

predicate func_4(Variable vs_289, Variable vheader_290, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(FunctionCall).getTarget().hasName("Stream_Buffer")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_289
		and target_4.getAnOperand().(VariableAccess).getTarget()=vheader_290
}

predicate func_5(Variable vpacketLength_291, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacketLength_291
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

from Function func, Variable vs_289, Variable vheader_290, Variable vpacketLength_291, LogicalOrExpr target_1, BlockStmt target_2, NotExpr target_3, PointerArithmeticOperation target_4, ExprStmt target_5
where
not func_0(vheader_290, vpacketLength_291, target_2, target_3, target_4, target_5, target_1)
and func_1(vs_289, vpacketLength_291, target_2, target_1)
and func_2(vs_289, target_2)
and func_3(vs_289, vheader_290, target_3)
and func_4(vs_289, vheader_290, target_4)
and func_5(vpacketLength_291, target_5)
and vs_289.getType().hasName("wStream *")
and vheader_290.getType().hasName("const size_t")
and vpacketLength_291.getType().hasName("size_t")
and vs_289.getParentScope+() = func
and vheader_290.getParentScope+() = func
and vpacketLength_291.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
