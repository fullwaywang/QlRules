/**
 * @name libtiff-d651abc097d91fac57f33b5f9447d0a9183f58e7-TIFFNumberOfStrips
 * @id cpp/libtiff/d651abc097d91fac57f33b5f9447d0a9183f58e7/TIFFNumberOfStrips
 * @description libtiff-d651abc097d91fac57f33b5f9447d0a9183f58e7-libtiff/tif_strip.c-TIFFNumberOfStrips CVE-2016-9273
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtd_63, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="td_nstrips"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getTarget().getName()="td_nstrips"
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtd_63, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_rowsperstrip"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="td_imagelength"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="4294967295"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_imagelength"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="td_rowsperstrip"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Variable vtd_63, ExprStmt target_1
where
not func_0(vtd_63, target_1, func)
and func_1(vtd_63, target_1)
and vtd_63.getType().hasName("TIFFDirectory *")
and vtd_63.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
