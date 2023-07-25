/**
 * @name wireshark-9fe2de783dbcbe74144678d60a4e3923367044b2-dissect_eap_identity_wlan
 * @id cpp/wireshark/9fe2de783dbcbe74144678d60a4e3923367044b2/dissect-eap-identity-wlan
 * @description wireshark-9fe2de783dbcbe74144678d60a4e3923367044b2-epan/dissectors/packet-eap.c-dissect_eap_identity_wlan CVE-2020-9428
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="3"
		and not target_0.getValue()="2"
		and target_0.getParent().(PointerAddExpr).getParent().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="%u"
		and not target_1.getValue()="%*3c%u"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="%u"
		and not target_2.getValue()="%*3c%u"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vtokens_545, ArrayExpr target_8, PointerArithmeticOperation target_6) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vtokens_545
		and target_3.getArrayOffset().(Literal).getValue()="2"
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sscanf")
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_4(Variable vtokens_545, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vtokens_545
		and target_4.getArrayOffset().(Literal).getValue()="2"
}

predicate func_5(Variable vtokens_545, ArrayExpr target_5) {
		target_5.getArrayBase().(VariableAccess).getTarget()=vtokens_545
		and target_5.getArrayOffset().(Literal).getValue()="3"
}

predicate func_6(Function func, PointerArithmeticOperation target_6) {
		target_6.getAnOperand() instanceof ArrayExpr
		and target_6.getAnOperand() instanceof Literal
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sscanf")
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, PointerArithmeticOperation target_7) {
		target_7.getAnOperand() instanceof ArrayExpr
		and target_7.getAnOperand().(Literal).getValue()="3"
		and target_7.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sscanf")
		and target_7.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vtokens_545, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vtokens_545
		and target_8.getArrayOffset().(Literal).getValue()="0"
}

from Function func, Variable vtokens_545, Literal target_0, StringLiteral target_1, StringLiteral target_2, ArrayExpr target_4, ArrayExpr target_5, PointerArithmeticOperation target_6, PointerArithmeticOperation target_7, ArrayExpr target_8
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_3(vtokens_545, target_8, target_6)
and func_4(vtokens_545, target_4)
and func_5(vtokens_545, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(vtokens_545, target_8)
and vtokens_545.getType().hasName("gchar **")
and vtokens_545.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
