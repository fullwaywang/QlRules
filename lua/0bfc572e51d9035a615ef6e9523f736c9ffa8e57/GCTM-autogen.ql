/**
 * @name lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-GCTM
 * @id cpp/lua/0bfc572e51d9035a615ef6e9523f736c9ffa8e57/GCTM
 * @description lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lgc.c-GCTM CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vg_900, Initializer target_0) {
		target_0.getExpr().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_0.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
}

/*predicate func_1(Variable vg_900, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="gcrunning"
		and target_1.getQualifier().(VariableAccess).getTarget()=vg_900
}

*/
predicate func_2(Variable vg_900, ExprStmt target_5, Literal target_2) {
		target_2.getValue()="0"
		and not target_2.getValue()="2"
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

/*predicate func_3(Variable vg_900, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="gcrunning"
		and target_3.getQualifier().(VariableAccess).getTarget()=vg_900
}

*/
predicate func_4(Variable vg_900, Variable vrunning_909, VariableAccess target_4) {
		target_4.getTarget()=vrunning_909
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
}

predicate func_5(Variable vg_900, Variable vrunning_909, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_900
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vrunning_909
}

from Function func, Variable vg_900, Variable vrunning_909, Initializer target_0, Literal target_2, VariableAccess target_4, ExprStmt target_5
where
func_0(vg_900, target_0)
and func_2(vg_900, target_5, target_2)
and func_4(vg_900, vrunning_909, target_4)
and func_5(vg_900, vrunning_909, target_5)
and vg_900.getType().hasName("global_State *")
and vrunning_909.getType().hasName("int")
and vg_900.(LocalVariable).getFunction() = func
and vrunning_909.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
