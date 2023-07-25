/**
 * @name lua-eb41999461b6f428186c55abd95f4ce1a76217d5-luaD_call
 * @id cpp/lua/eb41999461b6f428186c55abd95f4ce1a76217d5/luaD-call
 * @description lua-eb41999461b6f428186c55abd95f4ce1a76217d5-ldo.c-luaD_call CVE-2020-15888
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vL_457, Variable vci_488, PostfixIncrExpr target_9, ExprStmt target_10) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ci"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_0.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vci_488
		and target_0.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue() instanceof ConditionalExpr
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vL_457, Variable vci_488, ExprStmt target_10) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vci_488
		and target_1.getRValue() instanceof ConditionalExpr
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ci"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_1.getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

*/
predicate func_2(Parameter vL_457, Variable vci_488, ExprStmt target_11, ExprStmt target_10, ExprStmt target_12) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="ci"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_2.getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vci_488
		and target_2.getRValue().(AssignExpr).getRValue() instanceof ConditionalExpr
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vL_457, Variable vci_468, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ci"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vci_468
}

predicate func_4(Parameter vL_457, ConditionalExpr target_4) {
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="next"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ci"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_4.getThen().(PointerFieldAccess).getTarget().getName()="next"
		and target_4.getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ci"
		and target_4.getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_4.getElse().(FunctionCall).getTarget().hasName("luaE_extendCI")
		and target_4.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_457
}

predicate func_5(Parameter vL_457, ConditionalExpr target_5) {
		target_5.getCondition().(PointerFieldAccess).getTarget().getName()="next"
		and target_5.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ci"
		and target_5.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_5.getThen().(PointerFieldAccess).getTarget().getName()="next"
		and target_5.getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ci"
		and target_5.getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_5.getElse().(FunctionCall).getTarget().hasName("luaE_extendCI")
		and target_5.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_457
}

predicate func_6(Function func, Initializer target_6) {
		target_6.getExpr() instanceof ConditionalExpr
		and target_6.getExpr().getEnclosingFunction() = func
}

predicate func_7(Function func, Initializer target_7) {
		target_7.getExpr() instanceof ConditionalExpr
		and target_7.getExpr().getEnclosingFunction() = func
}

predicate func_8(Parameter vL_457, Variable vci_488, PostfixIncrExpr target_9, ExprStmt target_13, VariableAccess target_8) {
		target_8.getTarget()=vci_488
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ci"
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_9(Parameter vL_457, PostfixIncrExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
}

predicate func_10(Parameter vL_457, Variable vci_488, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ci"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vci_488
}

predicate func_11(Parameter vL_457, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("StkId")
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="stack"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_457
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ptrdiff_t")
}

predicate func_12(Variable vci_488, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="func"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_488
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("StkId")
}

predicate func_13(Parameter vL_457, Variable vci_488, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("luaV_execute")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_457
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vci_488
}

from Function func, Parameter vL_457, Variable vci_468, Variable vci_488, ExprStmt target_3, ConditionalExpr target_4, ConditionalExpr target_5, Initializer target_6, Initializer target_7, VariableAccess target_8, PostfixIncrExpr target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(vL_457, vci_488, target_9, target_10)
and not func_2(vL_457, vci_488, target_11, target_10, target_12)
and func_3(vL_457, vci_468, target_3)
and func_4(vL_457, target_4)
and func_5(vL_457, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(vL_457, vci_488, target_9, target_13, target_8)
and func_9(vL_457, target_9)
and func_10(vL_457, vci_488, target_10)
and func_11(vL_457, target_11)
and func_12(vci_488, target_12)
and func_13(vL_457, vci_488, target_13)
and vL_457.getType().hasName("lua_State *")
and vci_468.getType().hasName("CallInfo *")
and vci_488.getType().hasName("CallInfo *")
and vL_457.getFunction() = func
and vci_468.(LocalVariable).getFunction() = func
and vci_488.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
