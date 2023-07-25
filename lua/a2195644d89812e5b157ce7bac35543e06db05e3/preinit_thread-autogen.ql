/**
 * @name lua-a2195644d89812e5b157ce7bac35543e06db05e3-preinit_thread
 * @id cpp/lua/a2195644d89812e5b157ce7bac35543e06db05e3/preinit-thread
 * @description lua-a2195644d89812e5b157ce7bac35543e06db05e3-lstate.c-preinit_thread CVE-2020-15945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vL_288, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_288
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vL_288, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="errfunc"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_288
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vL_288, ExprStmt target_1
where
not func_0(vL_288, target_1, func)
and func_1(vL_288, target_1)
and vL_288.getType().hasName("lua_State *")
and vL_288.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
