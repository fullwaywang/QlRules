/**
 * @name lua-a6da1472c0c5e05ff249325f979531ad51533110-remarkupvals
 * @id cpp/lua/a6da1472c0c5e05ff249325f979531ad51533110/remarkupvals
 * @description lua-a6da1472c0c5e05ff249325f979531ad51533110-lgc.c-remarkupvals CVE-2020-24371
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalAndExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(LogicalAndExpr target_2) {
		target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="marked"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("lua_State *")
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="56"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="openupval"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("lua_State *")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, LogicalAndExpr target_2
where
not func_0(target_2, func)
and func_2(target_2)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
