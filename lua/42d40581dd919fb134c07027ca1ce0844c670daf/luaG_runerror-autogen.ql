/**
 * @name lua-42d40581dd919fb134c07027ca1ce0844c670daf-luaG_runerror
 * @id cpp/lua/42d40581dd919fb134c07027ca1ce0844c670daf/luaG-runerror
 * @description lua-42d40581dd919fb134c07027ca1ce0844c670daf-ldebug.c-luaG_runerror CVE-2022-33099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(NotExpr target_3, Function func) {
	exists(EmptyStmt target_0 |
		target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vL_819, NotExpr target_3, ExprStmt target_2) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_1.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_819
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vL_819, Variable vci_820, Variable vmsg_821, NotExpr target_3, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("luaG_addinfo")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_819
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsg_821
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="source"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="l"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cl"
		and target_2.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("getcurrentline")
		and target_2.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vci_820
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vci_820, NotExpr target_3) {
		target_3.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="callstatus"
		and target_3.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_820
		and target_3.getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
}

from Function func, Parameter vL_819, Variable vci_820, Variable vmsg_821, ExprStmt target_2, NotExpr target_3
where
not func_0(target_3, func)
and not func_1(vL_819, target_3, target_2)
and func_2(vL_819, vci_820, vmsg_821, target_3, target_2)
and func_3(vci_820, target_3)
and vL_819.getType().hasName("lua_State *")
and vci_820.getType().hasName("CallInfo *")
and vmsg_821.getType().hasName("const char *")
and vL_819.getFunction() = func
and vci_820.(LocalVariable).getFunction() = func
and vmsg_821.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
