/**
 * @name freerdp-52dd312e11b7376db62eabda244b481386d28c86-urb_os_feature_descriptor_request
 * @id cpp/freerdp/52dd312e11b7376db62eabda244b481386d28c86/urb-os-feature-descriptor-request
 * @description freerdp-52dd312e11b7376db62eabda244b481386d28c86-channels/urbdrc/client/data_transfer.c-urb_os_feature_descriptor_request CVE-2020-11039
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vOutputBufferSize_1025, ExprStmt target_6, RelationalOperation target_7, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vOutputBufferSize_1025
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967259"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_1)
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable vOutputBufferSize_1025, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vOutputBufferSize_1025
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_7(Variable vOutputBufferSize_1025, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vOutputBufferSize_1025
}

from Function func, Variable vOutputBufferSize_1025, ExprStmt target_6, RelationalOperation target_7
where
not func_1(vOutputBufferSize_1025, target_6, target_7, func)
and func_6(vOutputBufferSize_1025, target_6)
and func_7(vOutputBufferSize_1025, target_7)
and vOutputBufferSize_1025.getType().hasName("UINT32")
and vOutputBufferSize_1025.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
