/**
 * @name lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lua_newstate
 * @id cpp/lua/0bfc572e51d9035a615ef6e9523f736c9ffa8e57/lua-newstate
 * @description lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lstate.c-lua_newstate CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Variable vg_358, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="gcrunning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vg_358
}

*/
predicate func_1(Variable vg_358, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="2"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gcrunning"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_358
}

from Function func, Variable vg_358, Literal target_1
where
func_1(vg_358, target_1)
and vg_358.getType().hasName("global_State *")
and vg_358.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
