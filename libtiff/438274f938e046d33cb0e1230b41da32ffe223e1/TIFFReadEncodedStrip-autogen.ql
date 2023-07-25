/**
 * @name libtiff-438274f938e046d33cb0e1230b41da32ffe223e1-TIFFReadEncodedStrip
 * @id cpp/libtiff/438274f938e046d33cb0e1230b41da32ffe223e1/TIFFReadEncodedStrip
 * @description libtiff-438274f938e046d33cb0e1230b41da32ffe223e1-libtiff/tif_read.c-TIFFReadEncodedStrip CVE-2016-10266
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtd_325, Variable vrowsperstrip_326, ExprStmt target_7, ExprStmt target_8) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="td_imagelength"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_325
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_326
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof Literal
		and target_0.getElse().(Literal).getValue()="0"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtd_325, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="td_imagelength"
		and target_1.getQualifier().(VariableAccess).getTarget()=vtd_325
}

predicate func_2(Variable vrowsperstrip_326, VariableAccess target_2) {
		target_2.getTarget()=vrowsperstrip_326
}

predicate func_3(Variable vrowsperstrip_326, VariableAccess target_3) {
		target_3.getTarget()=vrowsperstrip_326
}

predicate func_5(Variable vtd_325, Variable vrowsperstrip_326, SubExpr target_5) {
		target_5.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_imagelength"
		and target_5.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_325
		and target_5.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrowsperstrip_326
		and target_5.getRightOperand() instanceof Literal
}

predicate func_7(Variable vtd_325, Variable vrowsperstrip_326, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="td_imagelength"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_325
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_326
}

predicate func_8(Variable vrowsperstrip_326, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_8.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand() instanceof SubExpr
		and target_8.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_326
}

from Function func, Variable vtd_325, Variable vrowsperstrip_326, PointerFieldAccess target_1, VariableAccess target_2, VariableAccess target_3, SubExpr target_5, ExprStmt target_7, ExprStmt target_8
where
not func_0(vtd_325, vrowsperstrip_326, target_7, target_8)
and func_1(vtd_325, target_1)
and func_2(vrowsperstrip_326, target_2)
and func_3(vrowsperstrip_326, target_3)
and func_5(vtd_325, vrowsperstrip_326, target_5)
and func_7(vtd_325, vrowsperstrip_326, target_7)
and func_8(vrowsperstrip_326, target_8)
and vtd_325.getType().hasName("TIFFDirectory *")
and vrowsperstrip_326.getType().hasName("uint32")
and vtd_325.(LocalVariable).getFunction() = func
and vrowsperstrip_326.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
