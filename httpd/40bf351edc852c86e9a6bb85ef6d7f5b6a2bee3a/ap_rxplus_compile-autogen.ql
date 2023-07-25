/**
 * @name httpd-40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a-ap_rxplus_compile
 * @id cpp/httpd/40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a/ap-rxplus-compile
 * @description httpd-40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a-server/util_regex.c-ap_rxplus_compile CVE-2020-1927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_46, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_0.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ap_regcomp_get_default_cflags")
		and target_0.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vret_46, AddressOfExpr target_5, AddressOfExpr target_6) {
	exists(BitwiseOrExpr target_1 |
		target_1.getLeftOperand().(Literal).getValue()="1024"
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("ap_regcomp")
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rx"
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vret_46, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="flags"
		and target_2.getQualifier().(VariableAccess).getTarget()=vret_46
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("ap_regcomp")
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rx"
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_3(Variable vret_46, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="subs"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("apr_pstrmemdup")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("apr_pool_t *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_4(Variable vret_46, ExprStmt target_4) {
		target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
		and target_4.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1"
}

predicate func_5(Variable vret_46, AddressOfExpr target_5) {
		target_5.getOperand().(PointerFieldAccess).getTarget().getName()="rx"
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
}

predicate func_6(Variable vret_46, AddressOfExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="rx"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_46
}

from Function func, Variable vret_46, PointerFieldAccess target_2, ExprStmt target_3, ExprStmt target_4, AddressOfExpr target_5, AddressOfExpr target_6
where
not func_0(vret_46, target_3, target_4, func)
and not func_1(vret_46, target_5, target_6)
and func_2(vret_46, target_2)
and func_3(vret_46, target_3)
and func_4(vret_46, target_4)
and func_5(vret_46, target_5)
and func_6(vret_46, target_6)
and vret_46.getType().hasName("ap_rxplus_t *")
and vret_46.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
