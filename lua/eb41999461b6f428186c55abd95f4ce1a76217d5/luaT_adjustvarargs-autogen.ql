/**
 * @name lua-eb41999461b6f428186c55abd95f4ce1a76217d5-luaT_adjustvarargs
 * @id cpp/lua/eb41999461b6f428186c55abd95f4ce1a76217d5/luaT-adjustvarargs
 * @description lua-eb41999461b6f428186c55abd95f4ce1a76217d5-ltm.c-luaT_adjustvarargs CVE-2020-15888
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_7, Function func, ExprStmt target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_0.getEnclosingFunction() = func
}

predicate func_1(RelationalOperation target_7, Function func, ExprStmt target_1) {
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vL_237, IfStmt target_2) {
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="GCdebt"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="l_G"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_237
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("luaC_step")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_237
		and target_2.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
}

/*predicate func_3(Parameter vL_237, RelationalOperation target_7, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("luaC_step")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_237
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

*/
predicate func_5(Function func, ExprStmt target_5) {
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getEnclosingFunction() = func
}

predicate func_6(RelationalOperation target_8, Function func, EmptyStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vL_237, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="GCdebt"
		and target_7.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="l_G"
		and target_7.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_237
		and target_7.getLesserOperand() instanceof Literal
}

predicate func_8(Parameter vL_237, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="stack_last"
		and target_8.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_237
		and target_8.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_8.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_237
		and target_8.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="maxstacksize"
		and target_8.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("const Proto *")
		and target_8.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vL_237, ExprStmt target_0, ExprStmt target_1, IfStmt target_2, ExprStmt target_5, EmptyStmt target_6, RelationalOperation target_7, RelationalOperation target_8
where
func_0(target_7, func, target_0)
and func_1(target_7, func, target_1)
and func_2(vL_237, target_2)
and func_5(func, target_5)
and func_6(target_8, func, target_6)
and func_7(vL_237, target_7)
and func_8(vL_237, target_8)
and vL_237.getType().hasName("lua_State *")
and vL_237.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
