/**
 * @name lua-a585eae6e7ada1ca9271607a4f48dfb17868ab7b-luaG_findlocal
 * @id cpp/lua/a585eae6e7ada1ca9271607a4f48dfb17868ab7b/luaG-findlocal
 * @description lua-a585eae6e7ada1ca9271607a4f48dfb17868ab7b-ldebug.c-luaG_findlocal CVE-2020-24370
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vn_200, VariableAccess target_0) {
		target_0.getTarget()=vn_200
		and target_0.getParent().(UnaryMinusExpr).getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("findvararg")
		and target_0.getParent().(UnaryMinusExpr).getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("CallInfo *")
		and target_0.getParent().(UnaryMinusExpr).getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1) instanceof UnaryMinusExpr
		and target_0.getParent().(UnaryMinusExpr).getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("StkId *")
}

predicate func_1(Parameter vn_200, UnaryMinusExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vn_200
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("findvararg")
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("CallInfo *")
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("StkId *")
}

from Function func, Parameter vn_200, VariableAccess target_0, UnaryMinusExpr target_1
where
func_0(vn_200, target_0)
and func_1(vn_200, target_1)
and vn_200.getType().hasName("int")
and vn_200.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
