/**
 * @name imagemagick-c4e63ad30bc42da691f2b5f82a24516dd6b4dc70-SetQuantumDepth
 * @id cpp/imagemagick/c4e63ad30bc42da691f2b5f82a24516dd6b4dc70/SetQuantumDepth
 * @description imagemagick-c4e63ad30bc42da691f2b5f82a24516dd6b4dc70-MagickCore/quantum.c-SetQuantumDepth CVE-2016-7530
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_656, ExprStmt target_6) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_0.getThen().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_0.getElse().(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimage_656, LogicalAndExpr target_7) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_1.getThen().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_1.getElse().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vimage_656, LogicalAndExpr target_7) {
	exists(ConditionalExpr target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_2.getThen().(PointerFieldAccess).getTarget().getName()="columns"
		and target_2.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_2.getElse().(PointerFieldAccess).getTarget().getName()="rows"
		and target_2.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vimage_656, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="columns"
		and target_3.getQualifier().(VariableAccess).getTarget()=vimage_656
}

predicate func_4(Parameter vimage_656, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="columns"
		and target_4.getQualifier().(VariableAccess).getTarget()=vimage_656
}

predicate func_5(Parameter vimage_656, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="columns"
		and target_5.getQualifier().(VariableAccess).getTarget()=vimage_656
}

predicate func_6(Parameter vimage_656, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
}

predicate func_7(Parameter vimage_656, LogicalAndExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_656
}

from Function func, Parameter vimage_656, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, ExprStmt target_6, LogicalAndExpr target_7
where
not func_0(vimage_656, target_6)
and not func_1(vimage_656, target_7)
and not func_2(vimage_656, target_7)
and func_3(vimage_656, target_3)
and func_4(vimage_656, target_4)
and func_5(vimage_656, target_5)
and func_6(vimage_656, target_6)
and func_7(vimage_656, target_7)
and vimage_656.getType().hasName("const Image *")
and vimage_656.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
