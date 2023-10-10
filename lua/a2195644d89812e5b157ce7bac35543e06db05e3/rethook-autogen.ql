/**
 * @name lua-a2195644d89812e5b157ce7bac35543e06db05e3-rethook
 * @id cpp/lua/a2195644d89812e5b157ce7bac35543e06db05e3/rethook
 * @description lua-a2195644d89812e5b157ce7bac35543e06db05e3-ldo.c-rethook CVE-2020-15945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vci_326, ExprStmt target_7) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vci_326
		and target_0.getRValue().(PointerFieldAccess).getTarget().getName()="previous"
		and target_0.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_326
		and target_7.getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vL_326, Parameter vci_326, ExprStmt target_8, PointerArithmeticOperation target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_326
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="savedpc"
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="l"
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_326
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="code"
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getRValue().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="l"
		and target_1.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vci_326, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="previous"
		and target_2.getQualifier().(VariableAccess).getTarget()=vci_326
}

predicate func_3(Parameter vL_326, Parameter vci_326, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="oldpc"
		and target_3.getQualifier().(VariableAccess).getTarget()=vL_326
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="savedpc"
		and target_3.getParent().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="l"
		and target_3.getParent().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_3.getParent().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="previous"
		and target_3.getParent().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_326
}

/*predicate func_4(Parameter vci_326, VariableAccess target_4) {
		target_4.getTarget()=vci_326
}

*/
predicate func_5(Parameter vL_326, Parameter vci_326, AssignExpr target_5) {
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="oldpc"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_326
		and target_5.getRValue().(ValueFieldAccess).getTarget().getName()="savedpc"
		and target_5.getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="l"
		and target_5.getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_5.getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="previous"
		and target_5.getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_326
}

/*predicate func_6(Parameter vci_326, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="previous"
		and target_6.getQualifier().(VariableAccess).getTarget()=vci_326
}

*/
predicate func_7(Parameter vci_326, ExprStmt target_7) {
		target_7.getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="func"
		and target_7.getExpr().(AssignPointerSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_326
		and target_7.getExpr().(AssignPointerSubExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_8(Parameter vL_326, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("luaD_hook")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_326
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_8.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_8.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_9(Parameter vL_326, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="stack"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_326
		and target_9.getAnOperand().(VariableAccess).getTarget().getType().hasName("ptrdiff_t")
}

from Function func, Parameter vL_326, Parameter vci_326, PointerFieldAccess target_2, PointerFieldAccess target_3, AssignExpr target_5, ExprStmt target_7, ExprStmt target_8, PointerArithmeticOperation target_9
where
not func_0(vci_326, target_7)
and not func_1(vL_326, vci_326, target_8, target_9)
and func_2(vci_326, target_2)
and func_3(vL_326, vci_326, target_3)
and func_5(vL_326, vci_326, target_5)
and func_7(vci_326, target_7)
and func_8(vL_326, target_8)
and func_9(vL_326, target_9)
and vL_326.getType().hasName("lua_State *")
and vci_326.getType().hasName("CallInfo *")
and vL_326.getFunction() = func
and vci_326.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
