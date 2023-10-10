/**
 * @name ffmpeg-d1c95d2ce39560e251fdb14f4af91b04fd7b845c-decode_wdlt
 * @id cpp/ffmpeg/d1c95d2ce39560e251fdb14f4af91b04fd7b845c/decode-wdlt
 * @description ffmpeg-d1c95d2ce39560e251fdb14f4af91b04fd7b845c-libavcodec/dfa.c-decode_wdlt CVE-2012-2786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vframe_224, Variable vframe_end_226, ExprStmt target_1, ExprStmt target_2, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vframe_end_226
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vframe_224
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vframe_224, ExprStmt target_1) {
		target_1.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vframe_224
		and target_1.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget().getType().hasName("unsigned int")
}

predicate func_2(Parameter vframe_224, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vframe_224
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255"
}

predicate func_3(Parameter vframe_224, Variable vframe_end_226, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vframe_end_226
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vframe_224
		and target_3.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
}

from Function func, Parameter vframe_224, Variable vframe_end_226, ExprStmt target_1, ExprStmt target_2, RelationalOperation target_3
where
not func_0(vframe_224, vframe_end_226, target_1, target_2, target_3)
and func_1(vframe_224, target_1)
and func_2(vframe_224, target_2)
and func_3(vframe_224, vframe_end_226, target_3)
and vframe_224.getType().hasName("uint8_t *")
and vframe_end_226.getType().hasName("const uint8_t *")
and vframe_224.getFunction() = func
and vframe_end_226.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
