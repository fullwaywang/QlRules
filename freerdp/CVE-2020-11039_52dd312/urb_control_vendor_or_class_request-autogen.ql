/**
 * @name freerdp-52dd312e11b7376db62eabda244b481386d28c86-urb_control_vendor_or_class_request
 * @id cpp/freerdp/52dd312e11b7376db62eabda244b481386d28c86/urb-control-vendor-or-class-request
 * @description freerdp-52dd312e11b7376db62eabda244b481386d28c86-channels/urbdrc/client/data_transfer.c-urb_control_vendor_or_class_request CVE-2020-11039
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vOutputBufferSize_946, ExprStmt target_1, RelationalOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vOutputBufferSize_946
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967259"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vOutputBufferSize_946, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vOutputBufferSize_946
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_2(Variable vOutputBufferSize_946, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vOutputBufferSize_946
}

from Function func, Variable vOutputBufferSize_946, ExprStmt target_1, RelationalOperation target_2
where
not func_0(vOutputBufferSize_946, target_1, target_2, func)
and func_1(vOutputBufferSize_946, target_1)
and func_2(vOutputBufferSize_946, target_2)
and vOutputBufferSize_946.getType().hasName("UINT32")
and vOutputBufferSize_946.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
