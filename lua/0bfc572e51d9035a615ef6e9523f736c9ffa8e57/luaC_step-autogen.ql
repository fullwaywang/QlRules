/**
 * @name lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-luaC_step
 * @id cpp/lua/0bfc572e51d9035a615ef6e9523f736c9ffa8e57/luaC-step
 * @description lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lgc.c-luaC_step CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vg_1679, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="gcrunning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vg_1679
}

predicate func_1(Variable vg_1679, LogicalOrExpr target_2) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="gcstp"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1679
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vg_1679, LogicalOrExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="gckind"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1679
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="lastatomic"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_1679
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vg_1679, PointerFieldAccess target_0, LogicalOrExpr target_2
where
func_0(vg_1679, target_0)
and not func_1(vg_1679, target_2)
and func_2(vg_1679, target_2)
and vg_1679.getType().hasName("global_State *")
and vg_1679.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
