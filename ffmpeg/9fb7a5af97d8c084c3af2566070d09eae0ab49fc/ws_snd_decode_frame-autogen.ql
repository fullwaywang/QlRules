/**
 * @name ffmpeg-9fb7a5af97d8c084c3af2566070d09eae0ab49fc-ws_snd_decode_frame
 * @id cpp/ffmpeg/9fb7a5af97d8c084c3af2566070d09eae0ab49fc/ws-snd-decode-frame
 * @description ffmpeg-9fb7a5af97d8c084c3af2566070d09eae0ab49fc-libavcodec/ws-snd1.c-ws_snd_decode_frame CVE-2012-0848
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_108, ExprStmt target_4) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand() instanceof Literal
		and target_0.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_108
		and target_0.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcount_108, ExprStmt target_5) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_108
		and target_1.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vcount_108, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_108
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="63"
}

predicate func_5(Variable vcount_108, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_108
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="32"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_108
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vcount_108, ExprStmt target_4, ExprStmt target_5
where
not func_0(vcount_108, target_4)
and not func_1(vcount_108, target_5)
and func_4(vcount_108, target_4)
and func_5(vcount_108, target_5)
and vcount_108.getType().hasName("uint8_t")
and vcount_108.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
