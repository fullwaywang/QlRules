/**
 * @name php-124fb22a13fafa3648e4e15b4f207c7096d8155e-isinsets
 * @id cpp/php/124fb22a13fafa3648e4e15b4f207c7096d8155e/isinsets
 * @description php-124fb22a13fafa3648e4e15b4f207c7096d8155e-ext/ereg/regex/regcomp.c-isinsets CVE-2015-1352
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vg_0, DivExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="setbits"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_0
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vg_0, DivExpr target_1) {
		target_1.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ncsets"
		and target_1.getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_0
		and target_1.getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getValue()="7"
		and target_1.getRightOperand().(Literal).getValue()="8"
}

predicate func_2(Parameter vg_0, ExprStmt target_2) {
		target_2.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uch *")
		and target_2.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="setbits"
		and target_2.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_0
}

from Function func, Parameter vg_0, DivExpr target_1, ExprStmt target_2
where
not func_0(vg_0, target_1, target_2, func)
and func_1(vg_0, target_1)
and func_2(vg_0, target_2)
and vg_0.getType().hasName("re_guts *")
and vg_0.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
