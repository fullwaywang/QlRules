/**
 * @name lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-f_luaopen
 * @id cpp/lua/0bfc572e51d9035a615ef6e9523f736c9ffa8e57/f-luaopen
 * @description lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lstate.c-f_luaopen CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Variable vg_232, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="gcrunning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vg_232
}

*/
predicate func_1(Variable vg_232, ExprStmt target_2, AddressOfExpr target_3, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_232
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Variable vg_232, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("init_registry")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("lua_State *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_232
}

predicate func_3(Variable vg_232, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="nilvalue"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_232
}

from Function func, Variable vg_232, Literal target_1, ExprStmt target_2, AddressOfExpr target_3
where
func_1(vg_232, target_2, target_3, target_1)
and func_2(vg_232, target_2)
and func_3(vg_232, target_3)
and vg_232.getType().hasName("global_State *")
and vg_232.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
