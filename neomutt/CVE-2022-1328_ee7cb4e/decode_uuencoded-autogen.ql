/**
 * @name neomutt-ee7cb4e461c1cdf0ac14817b03687d5908b85f84-decode_uuencoded
 * @id cpp/neomutt/ee7cb4e461c1cdf0ac14817b03687d5908b85f84/decode-uuencoded
 * @description neomutt-ee7cb4e461c1cdf0ac14817b03687d5908b85f84-handler.c-decode_uuencoded CVE-2022-1328
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpt_368, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpt_368
		and target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpt_368, BlockStmt target_5, PointerDereferenceExpr target_6) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpt_368
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpt_368
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getParent().(ForStmt).getStmt()=target_5
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_6.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlinelen_391, Variable vc_393, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vc_393
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vlinelen_391
}

predicate func_3(Variable vl_395, BlockStmt target_5, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vl_395
		and target_3.getGreaterOperand().(Literal).getValue()="6"
		and target_3.getParent().(ForStmt).getStmt()=target_5
}

predicate func_4(Variable vpt_368, ExprStmt target_4) {
		target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpt_368
}

predicate func_5(Variable vpt_368, Variable vl_395, BlockStmt target_5) {
		target_5.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpt_368
		and target_5.getStmt(2).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("decode_byte")
		and target_5.getStmt(2).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpt_368
		and target_5.getStmt(2).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="6"
		and target_5.getStmt(2).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_395
}

predicate func_6(Variable vpt_368, PointerDereferenceExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vpt_368
}

from Function func, Variable vpt_368, Variable vlinelen_391, Variable vc_393, Variable vl_395, RelationalOperation target_2, RelationalOperation target_3, ExprStmt target_4, BlockStmt target_5, PointerDereferenceExpr target_6
where
not func_0(vpt_368, target_4)
and not func_1(vpt_368, target_5, target_6)
and func_2(vlinelen_391, vc_393, target_2)
and func_3(vl_395, target_5, target_3)
and func_4(vpt_368, target_4)
and func_5(vpt_368, vl_395, target_5)
and func_6(vpt_368, target_6)
and vpt_368.getType().hasName("char *")
and vlinelen_391.getType().hasName("const unsigned char")
and vc_393.getType().hasName("unsigned char")
and vl_395.getType().hasName("char")
and vpt_368.getParentScope+() = func
and vlinelen_391.getParentScope+() = func
and vc_393.getParentScope+() = func
and vl_395.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
