/**
 * @name lua-597a53bbc681089d85b082b46c2e2428dec43b86-GCTM
 * @id cpp/lua/597a53bbc681089d85b082b46c2e2428dec43b86/GCTM
 * @description lua-597a53bbc681089d85b082b46c2e2428dec43b86-lgc.c-GCTM CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vg_900, ExprStmt target_4) {
	exists(AssignOrExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="gcstp"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
		and target_0.getRValue() instanceof Literal
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vg_900, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="gcstp"
		and target_1.getQualifier().(VariableAccess).getTarget()=vg_900
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(Literal).getValue()="2"
}

predicate func_3(Variable vg_900, AssignExpr target_3) {
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="gcstp"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
		and target_3.getRValue() instanceof Literal
}

predicate func_4(Variable vg_900, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcstp"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vg_900, PointerFieldAccess target_1, AssignExpr target_3, ExprStmt target_4
where
not func_0(vg_900, target_4)
and func_1(vg_900, target_1)
and func_3(vg_900, target_3)
and func_4(vg_900, target_4)
and vg_900.getType().hasName("global_State *")
and vg_900.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
