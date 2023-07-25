/**
 * @name ffmpeg-38d18fb57863bb9c54e68ae44aa780c5c282a184-compute_ref_coefs
 * @id cpp/ffmpeg/38d18fb57863bb9c54e68ae44aa780c5c282a184/compute-ref-coefs
 * @description ffmpeg-38d18fb57863bb9c54e68ae44aa780c5c282a184-libavcodec/lpc.h-compute_ref_coefs CVE-2020-20445
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verr_139) {
	exists(DivExpr target_0 |
		target_0.getLeftOperand() instanceof UnaryMinusExpr
		and target_0.getRightOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getRightOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=verr_139
		and target_0.getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=verr_139
		and target_0.getRightOperand().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_1(Variable verr_139) {
	exists(DivExpr target_1 |
		target_1.getLeftOperand() instanceof UnaryMinusExpr
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(Literal).getValue()="0"
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=verr_139
		and target_1.getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=verr_139
		and target_1.getRightOperand().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_1.getParent().(AssignExpr).getRValue() = target_1)
}

predicate func_2(Variable vgen1_140, UnaryMinusExpr target_2) {
		target_2.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vgen1_140
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Variable vgen1_140, UnaryMinusExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vgen1_140
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_4(Variable verr_139, VariableAccess target_4) {
		target_4.getTarget()=verr_139
}

predicate func_5(Variable verr_139, VariableAccess target_5) {
		target_5.getTarget()=verr_139
}

predicate func_6(Variable verr_139, ExprStmt target_12, DivExpr target_6) {
		target_6.getLeftOperand() instanceof UnaryMinusExpr
		and target_6.getRightOperand().(VariableAccess).getTarget()=verr_139
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getRightOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_7(Variable verr_139, ExprStmt target_13, DivExpr target_7) {
		target_7.getLeftOperand() instanceof UnaryMinusExpr
		and target_7.getRightOperand().(VariableAccess).getTarget()=verr_139
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getRightOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_12(Variable verr_139, Variable vgen1_140, ExprStmt target_12) {
		target_12.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=verr_139
		and target_12.getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vgen1_140
		and target_12.getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getExpr().(AssignAddExpr).getRValue().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_13(Variable verr_139, Variable vgen1_140, ExprStmt target_13) {
		target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=verr_139
		and target_13.getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vgen1_140
		and target_13.getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

from Function func, Variable verr_139, Variable vgen1_140, UnaryMinusExpr target_2, UnaryMinusExpr target_3, VariableAccess target_4, VariableAccess target_5, DivExpr target_6, DivExpr target_7, ExprStmt target_12, ExprStmt target_13
where
not func_0(verr_139)
and not func_1(verr_139)
and func_2(vgen1_140, target_2)
and func_3(vgen1_140, target_3)
and func_4(verr_139, target_4)
and func_5(verr_139, target_5)
and func_6(verr_139, target_12, target_6)
and func_7(verr_139, target_13, target_7)
and func_12(verr_139, vgen1_140, target_12)
and func_13(verr_139, vgen1_140, target_13)
and verr_139.getType().hasName("LPC_TYPE")
and vgen1_140.getType().hasName("LPC_TYPE[32]")
and verr_139.getParentScope+() = func
and vgen1_140.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
